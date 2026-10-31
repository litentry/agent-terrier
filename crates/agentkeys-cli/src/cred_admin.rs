//! Credential and memory commands using shared capability-authorized worker transport.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use std::path::{Path, PathBuf};

use agentkeys_backend_client::{
    normalize_omni_0x, BackendClient, CapMintOp, CapMintRequest, CredFetchInput, CredStoreInput,
    MemoryGetInput,
};
use agentkeys_types::CredManifest;

fn configure_actor_client(
    client: BackendClient,
    device_key_file: Option<&str>,
    delegation_file: Option<&str>,
) -> Result<(BackendClient, String)> {
    match (device_key_file, delegation_file) {
        (Some(path), None) => {
            let key = agentkeys_core::device_crypto::DeviceKey::load(path)
                .context("load existing registered device key")?;
            let hash = key.device_key_hash()?;
            Ok((client.with_device_key(std::sync::Arc::new(key)), hash))
        }
        (None, Some(path)) => {
            let (key, delegation) = crate::delegation_admin::StoredDelegation::load(path)?;
            let hash = delegation.device_key_hash.clone();
            Ok((client.with_delegation(key, delegation), hash))
        }
        _ => anyhow::bail!("provide exactly one existing device key file or delegation file"),
    }
}

/// Fetch + decrypt the credential `service` the actor is authorized for, returning
/// the plaintext secret. `operator_omni` == `actor_omni` for a master-self fetch;
/// for an agent they are (master, agent). The omnis are normalized to the broker's
/// `0x`-prefixed shape (issue #200 — the bare-vs-0x drift normalizer).
#[allow(clippy::too_many_arguments)]
pub async fn cred_fetch(
    service: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_file: &str,
    session_bearer: &str,
    broker_url: &str,
    cred_url: &str,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        None, // memory_url
        None, // audit_url
        Some(cred_url.to_string()),
    );
    let (client, device_key_hash) = configure_actor_client(client, Some(device_key_file), None)?;
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
    // Dual-mode response (the #372 recipe applied to cred): a v3 blob comes
    // back as envelope_b64 — client-encrypted under the STORING master's
    // signer-derived KEK, which this caller cannot derive (the signer binds
    // sign-message to the session omni). Fail LOUD, never hand ciphertext up
    // as if it were the secret.
    let pt_b64 = match (result.plaintext_b64, result.envelope_b64) {
        (Some(pt), _) => pt,
        (None, Some(_)) => anyhow::bail!(
            "credential `{service}` is a v3 client-encrypted envelope — only the vaulting \
             master's session can derive its KEK; delegated decrypt lands with the #91 \
             KEK-release follow-up"
        ),
        (None, None) => anyhow::bail!(
            "cred fetch for `{service}` returned neither plaintext_b64 nor envelope_b64 — \
             worker/client version mismatch"
        ),
    };
    let bytes = STANDARD
        .decode(&pt_b64)
        .context("decode cred plaintext_b64")?;
    String::from_utf8(bytes).context("cred plaintext is not valid UTF-8")
}

/// Read owner canonical memory under the actor's own grant and device proof.
#[allow(clippy::too_many_arguments)]
pub async fn memory_canonical_get(
    namespace: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_file: Option<&str>,
    session_bearer: &str,
    broker_url: &str,
    memory_url: &str,
    delegation_file: Option<&str>,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        Some(memory_url.to_string()),
        None, // audit_url
        None,
    );
    let (client, device_key_hash) =
        configure_actor_client(client, device_key_file, delegation_file)?;
    let cap = client
        .cap_mint(
            CapMintOp::MemoryCanonicalGet,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service: agentkeys_backend_client::service_knowledge(namespace),
                device_key_hash,
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
            object_key: None,
        })
        .await
        .with_context(|| format!("memory worker canonical-get for namespace `{namespace}`"))?;
    let bytes = STANDARD
        .decode(&result.plaintext_b64)
        .context("decode memory plaintext_b64")?;
    String::from_utf8(bytes).context("memory plaintext is not valid UTF-8")
}

/// Append a proposal with actor proof; workers independently verify scope and stamp provenance.
#[allow(clippy::too_many_arguments)]
pub async fn memory_inbox_push(
    namespace: &str,
    key: &str,
    body: &str,
    kind: agentkeys_backend_client::protocol::ContextKind,
    operator_omni: &str,
    actor_omni: &str,
    device_key_file: &str,
    session_bearer: &str,
    broker_url: &str,
    memory_url: &str,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        Some(memory_url.to_string()),
        None, // audit_url
        None,
    );
    let (client, device_key_hash) = configure_actor_client(client, Some(device_key_file), None)?;
    let resp = memory_inbox_push_with(
        &client,
        namespace,
        key,
        body,
        kind,
        operator_omni,
        actor_omni,
        &device_key_hash,
        session_bearer,
    )
    .await?;
    Ok(format!(
        "pushed {} proposal to the master's inbox → {} (content_hash {})",
        kind.as_str(),
        resp.s3_key,
        resp.content_hash
    ))
}

/// The push core on an ALREADY-BUILT client — split out so the #573 daemon
/// absorption bridge (`agentkeys-daemon --propose-once`) can pass its
/// cap-PoP-configured client (#552 signer custody signs the PoP remotely; the
/// plain-session CLI wrapper above builds its own client). ONE owner of the
/// cap-mint + inbox-append sequence either way.
#[allow(clippy::too_many_arguments)]
pub async fn memory_inbox_push_with(
    client: &BackendClient,
    namespace: &str,
    key: &str,
    body: &str,
    kind: agentkeys_backend_client::protocol::ContextKind,
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
) -> Result<agentkeys_backend_client::protocol::MemoryInboxAppendResp> {
    // DISTINCT `proposal:<ns>` grant (never the `knowledge:<ns>` read grant) — built from
    // the bare namespace by the single shared helper so the spelling can't drift.
    let service = agentkeys_backend_client::protocol::service_proposal(namespace);
    let cap = client
        .cap_mint(
            CapMintOp::MemoryAppend,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service,
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            session_bearer,
        )
        .await
        .with_context(|| format!("cap-mint memory-append for inbox namespace `{namespace}`"))?;
    let plaintext_b64 = STANDARD.encode(body.as_bytes());
    client
        .memory_inbox_append(cap, key.to_string(), plaintext_b64, kind)
        .await
        .with_context(|| {
            format!("memory worker inbox-append for namespace `{namespace}` key `{key}`")
        })
}

/// Store a credential under an owner capability. The local worker encrypts plaintext.
#[allow(clippy::too_many_arguments)]
pub async fn cred_store(
    service: &str,
    secret: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_file: &str,
    session_bearer: &str,
    broker_url: &str,
    cred_url: &str,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        None, // memory_url
        None, // audit_url
        Some(cred_url.to_string()),
    );
    let (client, device_key_hash) = configure_actor_client(client, Some(device_key_file), None)?;
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

#[cfg(test)]
mod device_configuration_tests {
    use super::*;

    #[tokio::test]
    async fn canonical_read_signs_the_knowledge_service_with_existing_key() {
        use agentkeys_backend_client::protocol::{BrokerCapRequest, MemoryGetBody};
        use axum::{
            http::{HeaderMap, StatusCode},
            routing::post,
            Json, Router,
        };
        use serde_json::json;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device");
        let key = std::sync::Arc::new(
            agentkeys_core::device_crypto::DeviceKey::load_or_generate(
                path.to_str().unwrap(),
                false,
            )
            .unwrap(),
        );
        let expected_key = key.clone();
        let router = Router::new()
            .route(
                "/v1/cap/memory-canonical-get",
                post(
                    move |headers: HeaderMap, Json(body): Json<BrokerCapRequest>| {
                        let key = expected_key.clone();
                        async move {
                            assert_eq!(headers["authorization"], "Bearer synthetic-session");
                            if body.service != "knowledge:notes" {
                                return (
                                    StatusCode::FORBIDDEN,
                                    Json(json!({"reason":"service_not_in_scope"})),
                                );
                            }
                            assert_eq!(body.device_key_hash, key.device_key_hash().unwrap());
                            assert_eq!(
                                body.client_sig.as_deref(),
                                Some(
                                    key.cap_pop_sig(
                                        &body.operator_omni,
                                        &body.actor_omni,
                                        &body.service,
                                        "canonical_fetch",
                                        "memory",
                                        body.client_nonce.as_deref().unwrap(),
                                        body.client_ts.unwrap(),
                                    )
                                    .unwrap()
                                    .as_str()
                                )
                            );
                            (StatusCode::OK, Json(json!({"synthetic":"capability"})))
                        }
                    },
                ),
            )
            .route(
                "/v1/memory/canonical-get",
                post(
                    |headers: HeaderMap, Json(body): Json<MemoryGetBody>| async move {
                        assert!(!headers.contains_key("authorization"));
                        assert_eq!(body.namespace, "notes");
                        assert_eq!(body.cap, json!({"synthetic":"capability"}));
                        Json(json!({"ok":true,"plaintext_b64":STANDARD.encode("canonical notes")}))
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let result = memory_canonical_get(
            "notes",
            &"11".repeat(32),
            &"22".repeat(32),
            Some(path.to_str().unwrap()),
            "synthetic-session",
            &url,
            &url,
            None,
        )
        .await
        .unwrap();
        assert_eq!(result, "canonical notes");
        task.abort();
    }

    #[test]
    fn commands_require_existing_device_key_and_do_not_create_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device");
        let client = || BackendClient::new(None, None, None, None);
        assert!(configure_actor_client(client(), Some(path.to_str().unwrap()), None).is_err());
        assert!(!path.exists());
        assert!(configure_actor_client(client(), None, None).is_err());
        assert!(configure_actor_client(client(), Some("unused"), Some("unused")).is_err());
        let key = agentkeys_core::device_crypto::DeviceKey::load_or_generate(
            path.to_str().unwrap(),
            false,
        )
        .unwrap();
        let (client, hash) =
            configure_actor_client(client(), Some(path.to_str().unwrap()), None).unwrap();
        assert_eq!(hash, key.device_key_hash().unwrap());
        assert_eq!(client.device_key.unwrap().device_key_hash().unwrap(), hash);
    }
}
