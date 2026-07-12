//! Master-side §10.2 agent admin (issue #144, method A): claim agent-initiated
//! pairing requests + pull pending bindings. These are the master's half of the
//! agent-initiated ceremony — the agent half (request + retrieve) lives in the
//! daemon's `--request-pairing` / `--retrieve-pairing` one-shots.
//!
//! Both commands are gated by the master's `J1` session bearer. The on-chain
//! binding and scope grant (the "bind" and "grant" steps the operator approves
//! with one Touch ID) stay in the chain helpers (`heima-agent-create.sh
//! --from-pubkey` and `heima-scope-set.sh --webauthn`) because chain submission
//! lives in shell + `cast`; those two helpers are the deterministic two-step
//! split the test drives. `agent pending` is the production-flow rendezvous: the
//! master discovers "agent-X wants to pair, wants `[scope]`" by pulling the broker.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("build http client")
}

/// Resolve the master `J1` bearer: explicit `session_bearer` if non-empty, else
/// the stored `master` session token.
fn resolve_bearer(session_bearer: &str) -> Result<String> {
    if !session_bearer.trim().is_empty() {
        return Ok(session_bearer.trim().to_string());
    }
    let sess = agentkeys_core::session_store::load_session("master")
        .context("no --session-bearer given and no stored `master` session to fall back on")?;
    Ok(sess.token.clone())
}

/// `agentkeys agent claim` — master claims an agent's pairing request by the
/// `pairing_code` the agent displayed, binding it under the HDKD child omni for
/// `label` and declaring the scope the agent should get. The agent never named
/// the master; this claim is the binding act (Sybil-safe).
pub async fn agent_claim(
    broker_url: &str,
    pairing_code: &str,
    label: &str,
    services: &str,
    session_bearer: &str,
) -> Result<String> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/pairing/claim"))
        .bearer_auth(bearer)
        .json(&json!({
            "pairing_code": pairing_code,
            "label": label,
            "requested_scope": services,
        }))
        .send()
        .await
        .context("POST /v1/agent/pairing/claim")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("agent claim failed: HTTP {status}: {text}"));
    }
    let v: Value = serde_json::from_str(&text).with_context(|| format!("parse: {text}"))?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys agent pending` — master pulls claimed-but-unbound agents (the
/// production push-notification substrate). Each row is "agent-X wants to pair,
/// wants `[requested_scope]`", with the device artifact (`device_pubkey`,
/// `pop_sig`, `device_key_hash`) the master needs to submit `registerAgentDevice`,
/// keyed by `request_id`.
pub async fn agent_pending(broker_url: &str, session_bearer: &str) -> Result<String> {
    let v = agent_pending_value(broker_url, session_bearer).await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// Same as [`agent_pending`] but returns the parsed broker response
/// (`{ "pending": [PendingBinding, …] }`) for programmatic callers — the daemon
/// ui-bridge maps it to the web UI's pairing-request shape (issue #214). The CLI
/// wrapper above pretty-prints this for the operator.
pub async fn agent_pending_value(broker_url: &str, session_bearer: &str) -> Result<Value> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .get(format!("{base}/v1/agent/pending-bindings"))
        .bearer_auth(bearer)
        .send()
        .await
        .context("GET /v1/agent/pending-bindings")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("agent pending failed: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("parse: {text}"))
}

/// `agentkeys agent accept` — the HEADLESS #225 E7 accept: build the sponsored
/// `executeBatch([registerAgentDevice, setScope])` UserOp on the broker, sign
/// its `userOpHash` with the SOFTWARE P-256 passkey (#164 headless/CI — an
/// on-disk key, never a hardware K11; the caller was warned on stderr), submit
/// to `EntryPoint.handleOps`, and ack the rendezvous row. This is the CLI twin
/// of the parent-control accept card, so CI + operators can run BOTH decoupled
/// pairings (#404) end-to-end with no browser:
///   - sandbox DELEGATE accept: `--services memory:...,inbox:...`
///   - channel-endpoint DEVICE accept (#408 D6): `--is-device
///     --services channel-pub:<id>[,channel-sub:<id>...]`
///
/// Acting as the accept card, it HARD-enforces §14.10: `--is-device` with zero
/// `channel-pub/sub:` grants is an error here (the broker's own layer only
/// warns), and a channel-only grant WITHOUT `--is-device` gets a loud stderr
/// nudge (it would bind a runtime-hosting delegate identity to a box that has
/// no runtime).
#[allow(clippy::too_many_arguments)]
pub async fn agent_accept(
    broker_url: &str,
    request_id: &str,
    services_csv: &str,
    is_device: bool,
    k11_key_file: &str,
    rp_id: &str,
    operator_omni_flag: &str,
    session_bearer: &str,
) -> Result<String> {
    use agentkeys_backend_client::protocol::{
        channel_grant_count, scope_is_device_only, AcceptAssertion, BuildAcceptUserOpRequest,
        BuildAcceptUserOpResponse, SubmitAcceptUserOpRequest,
    };
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let services: Vec<String> = services_csv
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    // §14.10 — this command IS the accept card in headless mode: hard-enforce.
    if is_device && channel_grant_count(&services) == 0 {
        return Err(anyhow!(
            "--is-device accept with ZERO channel grants (§14.10): a device is a channel \
             endpoint and must attach ≥1 `channel-pub:<id>` / `channel-sub:<id>` service \
             (got: {services:?})"
        ));
    }
    if !is_device && !services.is_empty() && scope_is_device_only(&services.join(",")) {
        eprintln!(
            "==> ⚠️  WARN: the grant set is channel-only but --is-device was not passed — \
             this binds as a DELEGATE (a sandbox may be ensured for it at poll/resolve). \
             If this actor is a camera/display/console, re-run with --is-device."
        );
    }

    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');

    // Operator omni: explicit flag, else the J1's own `agentkeys.omni_account`
    // claim (the same identity the broker authorizes the accept under).
    let operator_omni = if operator_omni_flag.trim().is_empty() {
        let payload_b64 = bearer
            .split('.')
            .nth(1)
            .ok_or_else(|| anyhow!("session bearer is not a JWT (no payload segment)"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64.trim_end_matches('='))
            .context("decode JWT payload")?;
        let claims: Value = serde_json::from_slice(&payload).context("parse JWT payload")?;
        claims["agentkeys"]["omni_account"]
            .as_str()
            .ok_or_else(|| {
                anyhow!("JWT carries no agentkeys.omni_account claim — pass --operator-omni")
            })?
            .to_string()
    } else {
        operator_omni_flag.trim().to_string()
    };

    // The binding artifact comes from the broker's AUTHORITATIVE pending row
    // (same source the daemon accept proxy uses) — never caller-supplied.
    let pending = agent_pending_value(broker_url, session_bearer).await?;
    let row = pending["pending"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r["request_id"].as_str() == Some(request_id))
        })
        .ok_or_else(|| {
            anyhow!(
                "no pending binding for request_id {request_id} — claim it first \
                 (`agentkeys agent claim`), or it was already accepted/declined"
            )
        })?
        .clone();
    let field = |k: &str| row[k].as_str().unwrap_or("").to_string();

    // 1. Build: the broker assembles + co-signs the sponsored op. The body is the
    //    one-owner protocol type (#203) — never a hand-rolled json! shape — so a
    //    wire change here is a compile error, not drift.
    let build_body = BuildAcceptUserOpRequest {
        operator_omni,
        actor_omni: field("child_omni"),
        device_key_hash: field("device_key_hash"),
        agent_pop_sig: field("pop_sig"),
        link_code_redemption: "0x".into(),
        services: services.clone(),
        read_only: false,
        max_per_call: "0".into(),
        max_per_period: "0".into(),
        max_total: "0".into(),
        period_seconds: 0,
        is_device,
    };
    let resp = client()?
        .post(format!("{base}/v1/accept/build"))
        .bearer_auth(&bearer)
        .json(&build_body)
        .send()
        .await
        .context("POST /v1/accept/build")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("accept build failed: HTTP {status}: {text}"));
    }
    let built: BuildAcceptUserOpResponse =
        serde_json::from_str(&text).with_context(|| format!("parse build: {text}"))?;
    let user_op_hash = built.user_op_hash.clone();

    // 2. Sign the userOpHash with the SOFTWARE passkey (headless K11 stand-in).
    let (auth_hex, cdj_hex, _loc, r_hex, s_hex) =
        crate::k11_webauthn::software_webauthn_sign(k11_key_file, &user_op_hash, rp_id)
            .map_err(|e| anyhow!("software-sign: {e}"))?;
    let r = hex::decode(&r_hex).context("r hex")?;
    let s = hex::decode(&s_hex).context("s hex")?;
    let sig = p256::ecdsa::Signature::from_scalars(
        *p256::FieldBytes::from_slice(&r),
        *p256::FieldBytes::from_slice(&s),
    )
    .map_err(|e| anyhow!("(r,s) → signature: {e}"))?;
    let assertion = AcceptAssertion {
        authenticator_data: URL_SAFE_NO_PAD.encode(hex::decode(&auth_hex).context("authData hex")?),
        client_data_json: URL_SAFE_NO_PAD
            .encode(hex::decode(&cdj_hex).context("clientDataJSON hex")?),
        signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
        // Informational only — the broker binds the operator-derived credIdHash,
        // never keccak(rawId) (see broker accept_assertion.rs).
        credential_id: URL_SAFE_NO_PAD.encode(b"software-passkey"),
    };

    // 3. Submit → EntryPoint.handleOps (blocks through the broker's receipt poll).
    let submit_body = SubmitAcceptUserOpRequest {
        user_op: built.user_op,
        assertion,
    };
    let resp = client()?
        .post(format!("{base}/v1/accept/submit"))
        .bearer_auth(&bearer)
        .json(&submit_body)
        .send()
        .await
        .context("POST /v1/accept/submit")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("accept submit failed: HTTP {status}: {text}"));
    }
    let submitted: Value =
        serde_json::from_str(&text).with_context(|| format!("parse submit: {text}"))?;

    // 4. Ack the rendezvous row so it stops reappearing in pending (best-effort —
    //    the on-chain accept already landed; a failed ack only leaves a stale card).
    if let Err(e) = agent_ack(broker_url, request_id, session_bearer).await {
        eprintln!(
            "==> ⚠️  accepted on-chain but ack failed ({e:#}) — the pending card may \
             reappear; decline it manually"
        );
    }

    let out = json!({
        "accepted": true,
        "is_device": is_device,
        "actor_omni": field("child_omni"),
        "label": field("label"),
        "services": services,
        "tx_hash": submitted["tx_hash"],
        "block_number": submitted["block_number"],
        "user_op_hash": submitted["user_op_hash"],
        // #97 control-plane audit receipts (DeviceAdd + ScopeGrant envelopes) —
        // verify on the audit page / audit worker by hash.
        "audit_envelope_hashes": submitted["audit_envelope_hashes"],
        "pending": submitted["pending"],
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// Shared headless tail of every build/submit ceremony: sign `user_op_hash`
/// with the SOFTWARE P-256 passkey (#164 headless/CI stand-in for the hardware
/// K11) and relay to the given submit route. Returns the broker's submit JSON.
async fn software_sign_and_submit(
    base: &str,
    bearer: &str,
    k11_key_file: &str,
    rp_id: &str,
    user_op: agentkeys_backend_client::protocol::WireUserOp,
    user_op_hash: &str,
    submit_path: &str,
) -> Result<Value> {
    use agentkeys_backend_client::protocol::{AcceptAssertion, SubmitAcceptUserOpRequest};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    let (auth_hex, cdj_hex, _loc, r_hex, s_hex) =
        crate::k11_webauthn::software_webauthn_sign(k11_key_file, user_op_hash, rp_id)
            .map_err(|e| anyhow!("software-sign: {e}"))?;
    let r = hex::decode(&r_hex).context("r hex")?;
    let s = hex::decode(&s_hex).context("s hex")?;
    let sig = p256::ecdsa::Signature::from_scalars(
        *p256::FieldBytes::from_slice(&r),
        *p256::FieldBytes::from_slice(&s),
    )
    .map_err(|e| anyhow!("(r,s) → signature: {e}"))?;
    let assertion = AcceptAssertion {
        authenticator_data: URL_SAFE_NO_PAD.encode(hex::decode(&auth_hex).context("authData hex")?),
        client_data_json: URL_SAFE_NO_PAD
            .encode(hex::decode(&cdj_hex).context("clientDataJSON hex")?),
        signature: URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()),
        credential_id: URL_SAFE_NO_PAD.encode(b"software-passkey"),
    };
    let submit_body = SubmitAcceptUserOpRequest { user_op, assertion };
    let resp = client()?
        .post(format!("{base}{submit_path}"))
        .bearer_auth(bearer)
        .json(&submit_body)
        .send()
        .await
        .with_context(|| format!("POST {submit_path}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("submit failed: HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).with_context(|| format!("parse submit: {text}"))
}

/// `agentkeys agent spawn` — the HEADLESS #427 delegate spawn: ONE ceremony,
/// zero rendezvous. The broker derives the child omni, generates the delegate
/// K10, pre-checks the agent-slot allowance (loud 409 when exhausted), and
/// assembles `executeBatch([registerDelegate, setScope])`; this signs the
/// `userOpHash` with the software passkey (#164 headless/CI — an on-disk key,
/// never a hardware K11) and submits. The CLI twin of the parent-control "New
/// agent" flow (#429), so CI + operators exercise the ceremony with no browser.
#[allow(clippy::too_many_arguments)]
pub async fn agent_spawn(
    broker_url: &str,
    label: &str,
    preset_id: &str,
    memory_ns: &str,
    memory_inherited: bool,
    k11_key_file: &str,
    rp_id: &str,
    session_bearer: &str,
) -> Result<String> {
    use agentkeys_backend_client::protocol::{BuildSpawnUserOpRequest, BuildSpawnUserOpResponse};

    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/').to_string();
    let operator_omni = operator_omni_from_bearer(&bearer)?;

    let build_body = BuildSpawnUserOpRequest {
        operator_omni,
        label: label.to_string(),
        preset_id: preset_id.to_string(),
        memory_ns: if memory_ns.trim().is_empty() {
            None
        } else {
            Some(memory_ns.trim().to_string())
        },
        memory_inherited,
    };
    let resp = client()?
        .post(format!("{base}/v1/agent/spawn/build"))
        .bearer_auth(&bearer)
        .json(&build_body)
        .send()
        .await
        .context("POST /v1/agent/spawn/build")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // The allowance 409 rides through verbatim — it already names the
        // quota + the actions (#425 loud-and-actionable acceptance).
        return Err(anyhow!("spawn build failed: HTTP {status}: {text}"));
    }
    let built: BuildSpawnUserOpResponse =
        serde_json::from_str(&text).with_context(|| format!("parse build: {text}"))?;

    let submitted = software_sign_and_submit(
        &base,
        &bearer,
        k11_key_file,
        rp_id,
        built.user_op,
        &built.user_op_hash,
        "/v1/agent/spawn/submit",
    )
    .await?;

    let out = json!({
        "spawned": true,
        "label": label,
        "preset_id": preset_id,
        "actor_omni": built.actor_omni,
        "device_key_hash": built.device_key_hash,
        "chat_channel_id": built.chat_channel_id,
        "memory_ns": built.memory_ns,
        "memory_inherited": built.memory_inherited,
        "services": built.services,
        "slots_used_before": built.slots_used,
        "slots_total": built.slots_total,
        "tx_hash": submitted["tx_hash"],
        "block_number": submitted["block_number"],
        "user_op_hash": submitted["user_op_hash"],
        "audit_envelope_hashes": submitted["audit_envelope_hashes"],
        // Gate provisioning + sandbox + DelegateSpawn anchor summary.
        "ceremony": submitted["ceremony"],
        "pending": submitted["pending"],
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// `agentkeys agent archive` — the HEADLESS #427 archive: revoke ONE delegate
/// (slot returns in-contract), record the keep-vs-delete resource choice
/// (#425 O4), deprovision its gate relay key, and tear down its sandbox.
pub async fn agent_archive(
    broker_url: &str,
    device_key_hash: &str,
    resources_kept: bool,
    memory_ns: &str,
    k11_key_file: &str,
    rp_id: &str,
    session_bearer: &str,
) -> Result<String> {
    use agentkeys_backend_client::protocol::{
        BuildArchiveUserOpRequest, BuildArchiveUserOpResponse,
    };

    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/').to_string();
    let operator_omni = operator_omni_from_bearer(&bearer)?;

    let build_body = BuildArchiveUserOpRequest {
        operator_omni,
        device_key_hash: device_key_hash.to_string(),
        resources_kept,
        memory_ns: if memory_ns.trim().is_empty() {
            None
        } else {
            Some(memory_ns.trim().to_string())
        },
    };
    let resp = client()?
        .post(format!("{base}/v1/agent/archive/build"))
        .bearer_auth(&bearer)
        .json(&build_body)
        .send()
        .await
        .context("POST /v1/agent/archive/build")?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("archive build failed: HTTP {status}: {text}"));
    }
    let built: BuildArchiveUserOpResponse =
        serde_json::from_str(&text).with_context(|| format!("parse build: {text}"))?;

    let submitted = software_sign_and_submit(
        &base,
        &bearer,
        k11_key_file,
        rp_id,
        built.user_op,
        &built.user_op_hash,
        "/v1/agent/archive/submit",
    )
    .await?;

    let out = json!({
        "archived": true,
        "device_key_hash": device_key_hash,
        "resources_kept": resources_kept,
        "tx_hash": submitted["tx_hash"],
        "block_number": submitted["block_number"],
        "user_op_hash": submitted["user_op_hash"],
        "audit_envelope_hashes": submitted["audit_envelope_hashes"],
        "ceremony": submitted["ceremony"],
        "pending": submitted["pending"],
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// The J1 bearer's own `agentkeys.omni_account` claim — the operator identity
/// the broker authorizes the ceremony under.
fn operator_omni_from_bearer(bearer: &str) -> Result<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let payload_b64 = bearer
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow!("session bearer is not a JWT (no payload segment)"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64.trim_end_matches('='))
        .context("decode JWT payload")?;
    let claims: Value = serde_json::from_slice(&payload).context("parse JWT payload")?;
    Ok(claims["agentkeys"]["omni_account"]
        .as_str()
        .ok_or_else(|| anyhow!("JWT carries no agentkeys.omni_account claim"))?
        .to_string())
}

/// `agentkeys agent ack` (programmatic) — the master acks a pending binding by
/// `request_id` after submitting `registerAgentDevice` on chain, clearing it from
/// the broker's pending list (§10.2 P.2). Used by the daemon web pairing flow
/// (#214) after a successful on-chain register.
pub async fn agent_ack(broker_url: &str, request_id: &str, session_bearer: &str) -> Result<()> {
    let bearer = resolve_bearer(session_bearer)?;
    let base = broker_url.trim_end_matches('/');
    let resp = client()?
        .post(format!("{base}/v1/agent/pending-bindings/ack"))
        .bearer_auth(bearer)
        .json(&json!({ "request_id": request_id }))
        .send()
        .await
        .context("POST /v1/agent/pending-bindings/ack")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(anyhow!("agent ack failed: HTTP {status}: {text}"));
    }
    Ok(())
}
