//! #512 — `POST /dev/sign-sts`: the signer-validated, INTENT-BASED STS mint
//! (ADR `docs/spec/stacks/ve-sts-signing-split.md`).
//!
//! The caller (broker mint-relay, #514) presents its session JWT (the standard
//! `/dev/*` bearer gate) plus an intent — `{data_class, verbs, ttl_seconds}` —
//! and the broker-minted OIDC token. The signer:
//!   1. verifies the session JWT and takes the ACTOR from its claim (rule 1);
//!   2. RENDERS the session policy itself from the intent via the shared
//!      per-cloud renderer (`agentkeys_core::session_policy`) — rule 2 holds
//!      by construction, no caller-authored policy string exists;
//!   3. resolves the per-class role + bucket (#511) from its own config
//!      (rule 4 — the caller never names a role);
//!   4. enforces the TTL ceiling (rule 5);
//!   5. performs the SigV4-signed `AssumeRoleWithOIDC` exchange itself — the
//!      AK/SK lives HERE, never on the broker (#514 moves it).
//!
//! Rule 3 (on-chain grant re-verify, Variant B+) lands in #513.
//!
//! ONE signer codebase, both stacks (`signer.litentry.org` / AWS today,
//! `signer.agentterrier.cn` / VE): cloud specificity enters only through the
//! renderer dialect + the exchange driver. Only the VE driver is live; the
//! AWS driver is gated on the #509 owner decision (default VE-only).
//!
//! Failure modes (every refusal loud, per the ADR table):
//!   503 `sts_signing_not_configured` · 401 (bearer) · 403 `actor_mismatch`
//!   · 400 `ttl_too_long` / `unknown_data_class` / `invalid_verbs`
//!   · 500 `role_class_mismatch` (config-sanity — unreachable via the API)
//!   · 502 `sts_exchange_failed`.

use axum::{extract::State, http::HeaderMap, http::StatusCode, Json};
use serde_json::{json, Value};

use agentkeys_core::session_policy::{
    render_session_policy, CloudDialect, ScopedAccessIntent, Verb,
};
use agentkeys_core::ve_sign::{self, VeSignRequest, DEFAULT_CONTENT_TYPE};
use agentkeys_protocol::{SignStsBody, SignStsResult};

use crate::handlers::dev_keys::{verify_session_jwt_claims, VerifiedSession};
use crate::state::SharedState;

/// VE STS API constants (VE's surface, not a wire shape we own — mirrors
/// `agentkeys-broker-server/src/ve_sts.rs`).
const STS_VERSION: &str = "2018-01-01";
pub const DEFAULT_STS_HOST: &str = "sts.volcengineapi.com";

/// One data class the signer may mint for: its per-class role (#511) + bucket.
#[derive(Clone, Debug)]
pub struct ClassBinding {
    pub class: String,
    pub role_trn: String,
    pub bucket: String,
}

/// Boot-time sign-sts config. Built ONCE from env in `main` (`from_env`);
/// tests construct the struct directly — never `std::env::set_var` (the
/// #258/#264 parallel-test rule).
#[derive(Clone, Debug)]
pub struct SignStsConfig {
    pub access_key: String,
    pub secret_key: String,
    pub region: String,
    pub host: String,
    pub oidc_provider_trn: String,
    pub ttl_ceiling: u64,
    /// Tests point this at a local stub (`http://127.0.0.1:<port>`); `None` =
    /// `https://{host}` (production). With an override the SIGNED Host header
    /// (`host` above) differs from the transport host — fine for stubs, which
    /// don't verify signatures; production never sets it.
    pub endpoint_override: Option<String>,
    /// #513 — Variant B+ rule 3: when true, every mint independently
    /// re-verifies the actor's on-chain binding before signing. Staged via
    /// `AGENTKEYS_SIGNER_REQUIRE_CHAIN_GRANT=1` (the REQUIRE_CAP_POP pattern).
    pub require_chain_grant: bool,
    /// Chain-read coordinates — required whenever the gate is armed.
    pub chain_rpc_url: Option<String>,
    pub registry_address: Option<String>,
    pub classes: Vec<ClassBinding>,
}

impl SignStsConfig {
    /// Env contract (the signer systemd unit): `AGENTKEYS_SIGNER_STS_PROVIDER=ve`
    /// arms the endpoint; unset/empty = disabled (`Ok(None)` → the handler
    /// 503s). PARTIAL config is FATAL (no-silent-fallback): armed means all of
    ///   `VOLCENGINE_ACCESS_KEY` / `VOLCENGINE_SECRET_KEY` (the relocated AK/SK)
    ///   `AGENTKEYS_VE_OIDC_PROVIDER_TRN`
    ///   `AGENTKEYS_STS_ROLE_TRN_{VAULT,MEMORY,CONFIG,CHANNEL}` (#511 TRNs)
    ///   `AGENTKEYS_STS_BUCKET_{VAULT,MEMORY,CONFIG,CHANNEL}`
    /// are present. Optional with defaults: `AGENTKEYS_VE_STS_REGION`
    /// (cn-beijing), `AGENTKEYS_VE_STS_HOST` (sts.volcengineapi.com),
    /// `AGENTKEYS_SIGNER_STS_TTL_CEILING` (900).
    pub fn from_env() -> Result<Option<Self>, String> {
        let provider = std::env::var("AGENTKEYS_SIGNER_STS_PROVIDER").unwrap_or_default();
        let provider = provider.trim().to_string();
        if provider.is_empty() {
            return Ok(None);
        }
        if provider != "ve" {
            return Err(format!(
                "AGENTKEYS_SIGNER_STS_PROVIDER={provider} — only \"ve\" is implemented \
                 (the AWS driver is gated on the #509 owner decision, default VE-only)"
            ));
        }
        let req = |k: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| format!("sign-sts armed but {k} is unset — partial config is fatal"))
        };
        let opt = |k: &str, default: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let ttl_ceiling = match std::env::var("AGENTKEYS_SIGNER_STS_TTL_CEILING") {
            Ok(v) if !v.trim().is_empty() => v
                .trim()
                .parse::<u64>()
                .map_err(|e| format!("AGENTKEYS_SIGNER_STS_TTL_CEILING: {e}"))?,
            _ => 900,
        };
        let require_chain_grant = matches!(
            std::env::var("AGENTKEYS_SIGNER_REQUIRE_CHAIN_GRANT").as_deref(),
            Ok("1") | Ok("true")
        );
        let (chain_rpc_url, registry_address) = if require_chain_grant {
            (
                Some(req("AGENTKEYS_CHAIN_RPC_HTTP")?),
                Some(req("AGENTKEYS_REGISTRY_ADDRESS")?),
            )
        } else {
            (None, None)
        };
        let mut classes = Vec::new();
        for class in ["vault", "memory", "config", "channel"] {
            let up = class.to_ascii_uppercase();
            classes.push(ClassBinding {
                class: class.to_string(),
                role_trn: req(&format!("AGENTKEYS_STS_ROLE_TRN_{up}"))?,
                bucket: req(&format!("AGENTKEYS_STS_BUCKET_{up}"))?,
            });
        }
        Ok(Some(Self {
            access_key: req("VOLCENGINE_ACCESS_KEY")?,
            secret_key: req("VOLCENGINE_SECRET_KEY")?,
            region: opt("AGENTKEYS_VE_STS_REGION", "cn-beijing"),
            host: opt("AGENTKEYS_VE_STS_HOST", DEFAULT_STS_HOST),
            oidc_provider_trn: req("AGENTKEYS_VE_OIDC_PROVIDER_TRN")?,
            ttl_ceiling,
            endpoint_override: None,
            require_chain_grant,
            chain_rpc_url,
            registry_address,
            classes,
        }))
    }
}

type ApiErr = (StatusCode, Json<Value>);

fn err_json(status: StatusCode, code: &str, message: String) -> ApiErr {
    // #513: every refusal is an audit row (journald-visible; the durable
    // audit-worker append rides #514).
    tracing::warn!(target: "agentkeys.signer.sign_sts", code, %message, "sign-sts refused");
    (status, Json(json!({ "error": code, "message": message })))
}

fn norm(s: &str) -> String {
    s.trim().trim_start_matches("0x").to_lowercase()
}

pub async fn sign_sts(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SignStsBody>,
) -> Result<Json<SignStsResult>, ApiErr> {
    let Some(cfg) = state.sign_sts.as_ref() else {
        return Err(err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "sts_signing_not_configured",
            "sign-sts is not armed on this signer — set AGENTKEYS_SIGNER_STS_PROVIDER=ve \
             plus the AK/SK + per-class role/bucket keys on the signer unit"
                .into(),
        ));
    };

    // Rule 1 + actor source: the session JWT. Mismatch is 403 actor_mismatch
    // per the ADR (a live JWT for the WRONG actor is an authorization failure,
    // not an authentication one — distinct from the legacy /dev/* 401 wrapper).
    let session = verify_session_jwt_claims(&state, &headers)?;
    if let Some(sess) = &session {
        if norm(&sess.omni_account) != norm(&body.omni_account) {
            return Err(err_json(
                StatusCode::FORBIDDEN,
                "actor_mismatch",
                "session JWT omni_account does not match the request omni_account".into(),
            ));
        }
    }
    let actor = norm(&body.omni_account);
    if actor.len() != 64 || !actor.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "invalid_actor",
            format!(
                "omni_account must be 64 hex chars (got {} chars)",
                actor.len()
            ),
        ));
    }

    // Rule 5: TTL ceiling.
    if body.ttl_seconds == 0 || body.ttl_seconds > cfg.ttl_ceiling {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "ttl_too_long",
            format!(
                "ttl_seconds {} outside (0, {}]",
                body.ttl_seconds, cfg.ttl_ceiling
            ),
        ));
    }

    // Class → role + bucket (#511). The caller never names a role — rule 4's
    // role↔class binding is the signer's own config.
    let class = body.data_class.trim().to_ascii_lowercase();
    let Some(binding) = cfg.classes.iter().find(|c| c.class == class) else {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "unknown_data_class",
            format!(
                "data_class {class:?} — expected one of vault|memory|config|channel \
                 (speech is gate-held on VE, #386)"
            ),
        ));
    };
    // Rule 4 config-sanity: the bound TRN must BE this class's role. Intent-
    // based requests cannot reach this — it fires only on a miswired unit env,
    // and loudly (a security event, not a validation nit).
    if !binding.role_trn.contains(&format!("-{class}-role")) {
        tracing::error!(
            class,
            role_trn = %binding.role_trn,
            "sign-sts CONFIG BUG: role TRN does not match its data class"
        );
        return Err(err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "role_class_mismatch",
            format!(
                "signer misconfiguration: role bound to class {class:?} is {:?}",
                binding.role_trn
            ),
        ));
    }

    let mut verbs: Vec<Verb> = Vec::new();
    for v in &body.verbs {
        match Verb::parse(v) {
            Some(parsed) if !verbs.contains(&parsed) => verbs.push(parsed),
            Some(_) => {}
            None => {
                return Err(err_json(
                    StatusCode::BAD_REQUEST,
                    "invalid_verbs",
                    format!("verb {v:?} — expected get|put|delete|list"),
                ));
            }
        }
    }
    if verbs.is_empty() {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "invalid_verbs",
            "verbs must name at least one of get|put|delete|list".into(),
        ));
    }

    // #513 — Variant B+ rule 3: independent on-chain re-verify at ISSUANCE,
    // staged behind AGENTKEYS_SIGNER_REQUIRE_CHAIN_GRANT=1 (the
    // REQUIRE_CAP_POP rollout pattern). Stateless — one read per mint,
    // amortized by the ≤TTL-ceiling credential lifetime; strictly less chain
    // load than layer 2's per-op verifies. NO grant-state caching.
    if cfg.require_chain_grant {
        chain_grant_gate(cfg, session.as_ref(), &actor, &class).await?;
    }

    // Rule 2 by construction: the signer renders the policy from the intent.
    let buckets = vec![binding.bucket.clone()];
    let policy = render_session_policy(
        CloudDialect::VeTos,
        &ScopedAccessIntent {
            actor_omni: &actor,
            buckets: &buckets,
            verbs: &verbs,
        },
    );

    // The exchange — SigV4-signed AssumeRoleWithOIDC, AK/SK signer-held.
    let duration = body.ttl_seconds.to_string();
    let query =
        ve_sign::canonical_query(&[("Action", "AssumeRoleWithOIDC"), ("Version", STS_VERSION)]);
    let form = ve_sign::form_encode(&[
        ("RoleTrn", binding.role_trn.as_str()),
        ("RoleSessionName", actor.as_str()),
        ("OIDCProviderTrn", cfg.oidc_provider_trn.as_str()),
        ("OIDCToken", body.oidc_token.as_str()),
        ("DurationSeconds", duration.as_str()),
        ("Policy", policy.as_str()),
    ]);
    let x_date = ve_sign::now_x_date();
    let signed = ve_sign::sign(&VeSignRequest {
        access_key_id: &cfg.access_key,
        secret_access_key: &cfg.secret_key,
        session_token: None,
        region: &cfg.region,
        service: "sts",
        host: &cfg.host,
        method: "POST",
        path: "/",
        query: &query,
        body: form.as_bytes(),
        content_type: DEFAULT_CONTENT_TYPE,
        x_date: &x_date,
    });
    let base = cfg
        .endpoint_override
        .clone()
        .unwrap_or_else(|| format!("https://{}", cfg.host));
    let url = format!("{base}/?{query}");
    let resp = reqwest::Client::new()
        .post(&url)
        .body(form)
        .header("Content-Type", &signed.content_type)
        .header("X-Date", &signed.x_date)
        .header("X-Content-Sha256", &signed.x_content_sha256)
        .header("Authorization", &signed.authorization)
        .send()
        .await
        .map_err(|e| {
            err_json(
                StatusCode::BAD_GATEWAY,
                "sts_exchange_failed",
                format!("VE STS send: {e}"),
            )
        })?;
    let text = resp.text().await.map_err(|e| {
        err_json(
            StatusCode::BAD_GATEWAY,
            "sts_exchange_failed",
            format!("VE STS read body: {e}"),
        )
    })?;
    let creds = parse_ve_assume(&text)
        .map_err(|m| err_json(StatusCode::BAD_GATEWAY, "sts_exchange_failed", m))?;
    // #513: the mint envelope — one audit row per SIGNATURE (refusals are
    // logged in err_json). Durable audit-worker append rides #514.
    tracing::info!(
        target: "agentkeys.signer.sign_sts",
        actor = %actor,
        class = %class,
        verbs = verbs.len(),
        ttl = body.ttl_seconds,
        expiration_unix = creds.expiration_unix,
        chain_grant_checked = cfg.require_chain_grant,
        outcome = "minted",
        "sign-sts minted scoped credentials"
    );
    Ok(Json(creds))
}

/// #513 — the chain-grant gate: the layer-2 on-chain view applied at
/// credential ISSUANCE. Agent sessions (JWT carries `device_pubkey` +
/// `parent_omni`) re-check the device binding — active, bound to BOTH the
/// session lineage and this actor, CAP_MINT role — via the SAME
/// `get_chain_device` read the workers use. Master sessions (no
/// `device_pubkey`) use master-self: `operatorMasterWallet(actor)` non-zero
/// (the #195 skip, mirrored at issuance). A broker-forged JWT thus obtains
/// nothing for an actor whose binding does not exist on chain.
async fn chain_grant_gate(
    cfg: &SignStsConfig,
    session: Option<&VerifiedSession>,
    actor: &str,
    class: &str,
) -> Result<(), ApiErr> {
    let (Some(rpc), Some(registry)) = (
        cfg.chain_rpc_url.as_deref(),
        cfg.registry_address.as_deref(),
    ) else {
        // from_env forbids this; only a hand-built config can reach it.
        return Err(err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signer_misconfigured",
            "require_chain_grant set but chain rpc/registry unset".into(),
        ));
    };
    let Some(sess) = session else {
        // The gate needs VERIFIED claims; with JWT auth disabled the signer
        // cannot attribute the mint — refuse loudly, never trust the body.
        return Err(err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "signer_misconfigured",
            "require_chain_grant needs the broker session pubkey loaded (JWT auth)".into(),
        ));
    };
    let http = reqwest::Client::new();
    match sess.device_pubkey.as_deref() {
        Some(device_pubkey) => {
            let parent = sess.parent_omni.as_deref().unwrap_or("");
            if parent.is_empty() {
                return Err(grant_refused(
                    actor,
                    class,
                    "agent session missing parent_omni lineage",
                ));
            }
            let dkh =
                agentkeys_core::device_crypto::device_key_hash(device_pubkey).map_err(|e| {
                    grant_refused(actor, class, &format!("bad device_pubkey claim: {e}"))
                })?;
            let device =
                agentkeys_worker_creds::verify::get_chain_device(&http, rpc, registry, &dkh)
                    .await
                    .map_err(|e| {
                        err_json(
                            StatusCode::BAD_GATEWAY,
                            "chain_read_failed",
                            format!("getDevice: {e}"),
                        )
                    })?;
            let bound = device.registered_at != 0
                && !device.revoked
                && device.actor_omni == norm(actor)
                && device.operator_omni == norm(parent)
                && (device.roles & agentkeys_worker_creds::verify::ROLE_CAP_MINT) != 0;
            if !bound {
                return Err(grant_refused(
                    actor,
                    class,
                    "on-chain device binding absent, revoked, or mismatched",
                ));
            }
        }
        None => {
            let wallet = call_operator_master_wallet(&http, rpc, registry, actor)
                .await
                .map_err(|e| {
                    err_json(
                        StatusCode::BAD_GATEWAY,
                        "chain_read_failed",
                        format!("operatorMasterWallet: {e}"),
                    )
                })?;
            if wallet.bytes().all(|b| b == b'0') {
                return Err(grant_refused(
                    actor,
                    class,
                    "no master account bound on chain for this omni",
                ));
            }
        }
    }
    tracing::info!(
        target: "agentkeys.signer.sign_sts",
        actor = %actor,
        class = %class,
        outcome = "chain_grant_ok",
        "sign-sts chain grant verified"
    );
    Ok(())
}

/// SECURITY EVENT (#513): in normal operation this cannot fire — a broker
/// minting for granted actors always passes rule 3. Loud + structured so it
/// is alertable, then the caller returns `403 grant_not_found`.
fn grant_refused(actor: &str, class: &str, reason: &str) -> ApiErr {
    tracing::error!(
        target: "agentkeys.signer.sign_sts",
        actor = %actor,
        class = %class,
        reason = %reason,
        outcome = "grant_not_found",
        "sign-sts REFUSED — independent chain re-verify failed"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "error": "grant_not_found",
            "message": format!("on-chain grant re-verify failed: {reason}"),
        })),
    )
}

/// `operatorMasterWallet(bytes32)` — bare JSON-RPC eth_call (the broker
/// cap.rs precedent for this view). Returns the 40-hex wallet (no 0x);
/// all-zeros = no master registered for the omni.
async fn call_operator_master_wallet(
    http: &reqwest::Client,
    rpc_url: &str,
    registry: &str,
    omni: &str,
) -> Result<String, String> {
    use sha2::digest::Digest as _;
    let omni = norm(omni);
    if omni.len() != 64 {
        return Err(format!("omni must be 64 hex chars, got {}", omni.len()));
    }
    let selector = {
        let mut h = sha3::Keccak256::new();
        h.update(b"operatorMasterWallet(bytes32)");
        hex::encode(&h.finalize()[..4])
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": registry, "data": format!("0x{selector}{omni}")}, "latest"],
        "id": 1,
    });
    let resp = http
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("rpc send: {e}"))?;
    let v: Value = resp.json().await.map_err(|e| format!("rpc body: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("rpc error: {err}"));
    }
    let word = v["result"]
        .as_str()
        .ok_or_else(|| format!("no result in rpc response: {v}"))?
        .trim_start_matches("0x")
        .to_lowercase();
    if word.len() < 40 {
        return Err(format!("result too short for an address word: {word:?}"));
    }
    Ok(word[word.len() - 40..].to_string())
}

/// Parse the VE `AssumeRoleWithOIDC` response. VE reports errors as
/// `ResponseMetadata.Error {Code, Message}` regardless of HTTP status; the
/// live expiry field is `Expiration` (RFC-3339, +08:00 offset) — `ExpiredTime`
/// (some VE docs) and numeric epochs are accepted too. Mirrors the broker's
/// `ve_sts::parse_assume_response` (VE's response shape, not a wire shape we
/// own).
fn parse_ve_assume(body: &str) -> Result<SignStsResult, String> {
    let v: Value = serde_json::from_str(body)
        .map_err(|e| format!("VE STS response is not JSON: {e} — body: {body}"))?;
    if let Some(err) = v["ResponseMetadata"]["Error"].as_object() {
        let code = err.get("Code").and_then(|c| c.as_str()).unwrap_or("?");
        let msg = err.get("Message").and_then(|m| m.as_str()).unwrap_or("?");
        return Err(format!("AssumeRoleWithOIDC failed: {code}: {msg}"));
    }
    let creds = &v["Result"]["Credentials"];
    let field = |k: &str| -> Result<String, String> {
        creds[k]
            .as_str()
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("VE STS response missing Result.Credentials.{k}: {body}"))
    };
    let expiry = ["Expiration", "ExpiredTime"]
        .iter()
        .find_map(|k| creds.get(*k).filter(|val| !val.is_null()));
    let expiration_unix = match expiry {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map_err(|e| format!("could not parse credential expiry {s:?} as RFC-3339: {e}"))?
            .timestamp(),
        other => {
            return Err(format!(
                "no Expiration/ExpiredTime in Credentials (got {other:?}) — full body: {body}"
            ))
        }
    };
    Ok(SignStsResult {
        access_key_id: field("AccessKeyId")?,
        secret_access_key: field("SecretAccessKey")?,
        session_token: field("SessionToken")?,
        expiration_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_signer_router;
    use crate::state::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn bindings() -> Vec<ClassBinding> {
        ["vault", "memory", "config", "channel"]
            .into_iter()
            .map(|c| ClassBinding {
                class: c.to_string(),
                role_trn: format!("trn:iam::1:role/agentterrier-{c}-role"),
                bucket: format!("agentterrier-{c}"),
            })
            .collect()
    }

    fn config(endpoint_override: Option<String>) -> SignStsConfig {
        SignStsConfig {
            access_key: "AKLTtest".into(),
            secret_key: "c2VjcmV0".into(),
            region: "cn-beijing".into(),
            host: DEFAULT_STS_HOST.into(),
            oidc_provider_trn: "trn:iam::1:oidc-provider/broker-agentterrier".into(),
            ttl_ceiling: 900,
            endpoint_override,
            require_chain_grant: false,
            chain_rpc_url: None,
            registry_address: None,
            classes: bindings(),
        }
    }

    fn state_with(cfg: Option<SignStsConfig>) -> crate::state::SharedState {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        Arc::new(AppState::new(conn).with_sign_sts(cfg))
    }

    async fn post(
        state: crate::state::SharedState,
        body: serde_json::Value,
    ) -> (axum::http::StatusCode, Value) {
        let resp = create_signer_router(state)
            .oneshot(
                Request::post("/dev/sign-sts")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    fn valid_body() -> serde_json::Value {
        serde_json::json!({
            "omni_account": "ab".repeat(32),
            "data_class": "config",
            "verbs": ["get", "put"],
            "ttl_seconds": 900,
            "oidc_token": "h.p.s",
        })
    }

    #[tokio::test]
    async fn unconfigured_returns_503_sts_signing_not_configured() {
        let (status, v) = post(state_with(None), valid_body()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"], "sts_signing_not_configured", "{v}");
    }

    #[tokio::test]
    async fn ttl_over_ceiling_is_400_ttl_too_long() {
        let mut b = valid_body();
        b["ttl_seconds"] = serde_json::json!(3600);
        let (status, v) = post(state_with(Some(config(None))), b).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"], "ttl_too_long", "{v}");
    }

    #[tokio::test]
    async fn unknown_class_is_400_and_names_the_gate_held_speech_plane() {
        let mut b = valid_body();
        b["data_class"] = serde_json::json!("speech");
        let (status, v) = post(state_with(Some(config(None))), b).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"], "unknown_data_class", "{v}");
        assert!(v["message"].as_str().unwrap().contains("#386"), "{v}");
    }

    #[tokio::test]
    async fn bad_verb_is_400_invalid_verbs() {
        let mut b = valid_body();
        b["verbs"] = serde_json::json!(["read"]);
        let (status, v) = post(state_with(Some(config(None))), b).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"], "invalid_verbs", "{v}");
    }

    #[tokio::test]
    async fn miswired_role_class_binding_is_500_role_class_mismatch() {
        let mut cfg = config(None);
        cfg.classes[2].role_trn = "trn:iam::1:role/agentterrier-vault-role".into(); // config→vault: wrong
        let (status, v) = post(state_with(Some(cfg)), valid_body()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(v["error"], "role_class_mismatch", "{v}");
    }

    #[tokio::test]
    async fn happy_path_mints_against_a_stub_and_normalizes_expiry() {
        // Local VE-STS stub: any POST → canned success (stubs don't verify
        // SigV4 — the signature itself is pinned by core's ve_sign tests +
        // the live conformance test).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stub = axum::Router::new().route(
            "/",
            axum::routing::post(|| async {
                Json(serde_json::json!({
                    "ResponseMetadata": { "Action": "AssumeRoleWithOIDC" },
                    "Result": { "Credentials": {
                        "AccessKeyId": "AKLTminted",
                        "SecretAccessKey": "sk-minted",
                        "SessionToken": "tok-minted",
                        "Expiration": "2026-07-18T20:00:00+08:00",
                    }}
                }))
            }),
        );
        tokio::spawn(async move { axum::serve(listener, stub).await.unwrap() });

        let (status, v) = post(
            state_with(Some(config(Some(format!("http://{addr}"))))),
            valid_body(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["access_key_id"], "AKLTminted", "{v}");
        assert_eq!(v["secret_access_key"], "sk-minted", "{v}");
        assert_eq!(v["session_token"], "tok-minted", "{v}");
        let expected = chrono::DateTime::parse_from_rfc3339("2026-07-18T20:00:00+08:00")
            .unwrap()
            .timestamp();
        assert_eq!(v["expiration_unix"], serde_json::json!(expected), "{v}");
    }

    #[test]
    fn parse_rejects_ve_error_envelope() {
        let body = r#"{"ResponseMetadata":{"Error":{"Code":"InvalidParameter","Message":"nope"}}}"#;
        let err = parse_ve_assume(body).unwrap_err();
        assert!(err.contains("InvalidParameter"), "{err}");
    }

    // ── #513 chain-grant gate (hermetic: p256 test JWT + local RPC stub) ──────

    fn es256_keys() -> (jsonwebtoken::EncodingKey, jsonwebtoken::DecodingKey) {
        use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
        let sk = p256::SecretKey::random(&mut rand_core::OsRng);
        let priv_pem = sk.to_pkcs8_pem(Default::default()).unwrap();
        let pub_pem = sk
            .public_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        (
            jsonwebtoken::EncodingKey::from_ec_pem(priv_pem.as_bytes()).unwrap(),
            jsonwebtoken::DecodingKey::from_ec_pem(pub_pem.as_bytes()).unwrap(),
        )
    }

    /// A MASTER session JWT: no device_pubkey/parent_omni → the gate takes the
    /// master-self path. (The agent path's getDevice ABI decode is pinned by
    /// agentkeys-worker-creds' own tests — not re-stubbed here.)
    fn master_jwt(enc: &jsonwebtoken::EncodingKey, omni: &str) -> String {
        let claims = serde_json::json!({
            "exp": 9_999_999_999u64,
            "aud": "agentkeys:broker",
            "agentkeys": { "omni_account": omni },
        });
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256),
            &claims,
            enc,
        )
        .unwrap()
    }

    async fn rpc_stub(word: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = axum::Router::new().route(
            "/",
            axum::routing::post(move || async move {
                Json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": word}))
            }),
        );
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    async fn post_auth(
        state: crate::state::SharedState,
        body: serde_json::Value,
        bearer: &str,
    ) -> (axum::http::StatusCode, Value) {
        let resp = create_signer_router(state)
            .oneshot(
                Request::post("/dev/sign-sts")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {bearer}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn chain_gate_master_self_passes_and_mints() {
        let (enc, dec) = es256_keys();
        let omni = "ab".repeat(32);
        // operatorMasterWallet → non-zero word = registered master.
        let rpc =
            rpc_stub("0x0000000000000000000000001111111111111111111111111111111111111111").await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sts = axum::Router::new().route(
            "/",
            axum::routing::post(|| async {
                Json(serde_json::json!({
                    "Result": { "Credentials": {
                        "AccessKeyId": "AK",
                        "SecretAccessKey": "SK",
                        "SessionToken": "T",
                        "Expiration": 1_789_000_000,
                    }}
                }))
            }),
        );
        tokio::spawn(async move { axum::serve(listener, sts).await.unwrap() });

        let mut cfg = config(Some(format!("http://{addr}")));
        cfg.require_chain_grant = true;
        cfg.chain_rpc_url = Some(rpc);
        cfg.registry_address = Some("0x0000000000000000000000000000000000000001".into());
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let state = Arc::new(
            AppState::new(conn)
                .with_broker_session_pubkey(Some(dec))
                .with_sign_sts(Some(cfg)),
        );
        let (status, v) = post_auth(state, valid_body(), &master_jwt(&enc, &omni)).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["access_key_id"], "AK", "{v}");
        assert_eq!(
            v["expiration_unix"],
            serde_json::json!(1_789_000_000),
            "{v}"
        );
    }

    #[tokio::test]
    async fn chain_gate_unregistered_actor_is_403_grant_not_found() {
        let (enc, dec) = es256_keys();
        let omni = "ab".repeat(32);
        // operatorMasterWallet → zero word = no master bound; a forged JWT
        // for an unbound actor obtains NOTHING (the B+ property).
        let rpc =
            rpc_stub("0x0000000000000000000000000000000000000000000000000000000000000000").await;
        let mut cfg = config(None);
        cfg.require_chain_grant = true;
        cfg.chain_rpc_url = Some(rpc);
        cfg.registry_address = Some("0x0000000000000000000000000000000000000001".into());
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let state = Arc::new(
            AppState::new(conn)
                .with_broker_session_pubkey(Some(dec))
                .with_sign_sts(Some(cfg)),
        );
        let (status, v) = post_auth(state, valid_body(), &master_jwt(&enc, &omni)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{v}");
        assert_eq!(v["error"], "grant_not_found", "{v}");
    }
}
