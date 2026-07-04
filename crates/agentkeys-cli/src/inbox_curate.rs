//! #339 P2 — the MASTER-side absorption-inbox curate verbs (`agentkeys memory
//! inbox-{list,view,accept,reject}`), the CLI twin of the web curate UI.
//!
//! These DRIVE THE LOCAL DAEMON's `/v1/master/inbox*` endpoints rather than the
//! broker/worker directly. Curate is a master-runtime operation, and the daemon
//! already OWNS the read→curate→GC semantics — in particular the per-namespace
//! read-modify-write MERGE + taxonomy reconcile in `plant_master_memory_inner`.
//! Re-implementing that merge here would be a #203-class second owner of the
//! curate contract, and a raw `memory_put` would OVERWRITE the whole namespace
//! blob with the single accepted entry, dropping every other canonical memory in
//! it. So the CLI is a thin client of the daemon, exactly like the web app.
//!
//! Contrast the DELEGATE-side `cred_admin::memory_inbox_push`, which talks to the
//! broker/worker directly (the A' shape) because a delegate runs in a sandbox with
//! no daemon. Push = delegate (broker-direct); curate = master (daemon-driven).

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};

/// Default ui-bridge address — the daemon's `--ui-bridge-bind` (see
/// `agentkeys-daemon` main.rs, default `127.0.0.1:3114`). Single source so the
/// port isn't re-spelled across the clap defaults and the unreachable-daemon hint.
pub const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:3114";

/// One request to a daemon inbox endpoint. Surfaces failures loudly: a transport
/// error (daemon down) and a non-2xx (no master session / worker failure) both
/// become a contextual `anyhow` error — never a silent empty result.
async fn daemon_call(method: reqwest::Method, url: &str, body: Option<Value>) -> Result<Value> {
    let client = reqwest::Client::new();
    let mut req = client.request(method, url);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req.send().await.with_context(|| {
        format!(
            "could not reach the daemon at {url} — is it running? \
             (ui-bridge default {DEFAULT_DAEMON_URL}; start it via dev.sh)"
        )
    })?;
    let status = resp.status();
    let value: Value = resp
        .json()
        .await
        .with_context(|| format!("daemon {url}: response body was not JSON"))?;
    if !status.is_success() {
        let err = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("(no error message)");
        let hint = if status.as_u16() == 409 {
            "\n  hint: the daemon has no active master session — open the web app and \
             authenticate with Touch ID, then retry (the daemon holds the master \
             session; these curate verbs drive it)."
        } else {
            ""
        };
        return Err(anyhow!("daemon {url} returned {status}: {err}{hint}"));
    }
    Ok(value)
}

/// `agentkeys memory inbox-list` → daemon `GET /v1/master/inbox`. Renders the
/// curate queue: the delegate proposals awaiting master review. Provenance
/// (`source_delegate_omni`, `ns`) is worker-stamped — a delegate cannot forge it.
pub async fn inbox_list(daemon_url: &str) -> Result<String> {
    let url = format!("{}/v1/master/inbox", daemon_url.trim_end_matches('/'));
    let value = daemon_call(reqwest::Method::GET, &url, None).await?;
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        return Ok(
            "absorption inbox is empty — no delegate proposals awaiting curation.".to_string(),
        );
    }
    let mut out = format!(
        "absorption inbox — {} proposal(s) awaiting curation:\n",
        items.len()
    );
    for (idx, it) in items.iter().enumerate() {
        let n = idx + 1;
        let ns = it.get("ns").and_then(Value::as_str).unwrap_or("?");
        let key = it.get("key").and_then(Value::as_str).unwrap_or("?");
        let from = it
            .get("source_delegate_omni")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let bytes = it.get("bytes").and_then(Value::as_u64).unwrap_or(0);
        let ts = it.get("ts").and_then(Value::as_u64).unwrap_or(0);
        let s3_key = it.get("s3_key").and_then(Value::as_str).unwrap_or("?");
        // #390 — per-kind curate policy at a glance (absent = knowledge).
        let kind = it
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("knowledge");
        let kind_note = match kind {
            "skill" => " · SKILL (view required before accept)",
            "persona" => " · PERSONA (never inbox-adoptable — reject)",
            _ => "",
        };
        out.push_str(&format!(
            "\n  [{n}] memory:{ns} / {key} · {kind}{kind_note}\n      \
             from delegate {from} · {bytes} bytes · ts {ts}\n      \
             s3_key: {s3_key}\n"
        ));
    }
    out.push_str(
        "\ncurate with:\n  \
         agentkeys memory inbox-view   --s3-key <s3_key>\n  \
         agentkeys memory inbox-accept --s3-key <s3_key>\n  \
         agentkeys memory inbox-reject --s3-key <s3_key>",
    );
    Ok(out)
}

/// `agentkeys memory inbox-view --s3-key …` → daemon `POST /v1/master/inbox/entry`.
/// Reads ONE proposal's full plaintext body so the master can review what was
/// pushed before accept/reject.
pub async fn inbox_view(daemon_url: &str, s3_key: &str) -> Result<String> {
    let url = format!("{}/v1/master/inbox/entry", daemon_url.trim_end_matches('/'));
    let value = daemon_call(
        reqwest::Method::POST,
        &url,
        Some(json!({ "s3_key": s3_key })),
    )
    .await?;
    let ns = value.get("ns").and_then(Value::as_str).unwrap_or("?");
    let key = value.get("key").and_then(Value::as_str).unwrap_or("?");
    let from = value
        .get("source_delegate_omni")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let content_hash = value
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or("?");
    let ts = value.get("ts").and_then(Value::as_u64).unwrap_or(0);
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("knowledge");
    let body = value.get("body").and_then(Value::as_str).unwrap_or("");
    let accept_hint = match kind {
        "skill" => format!(
            "\n\naccept this SKILL with the viewed-body watermark:\n  \
             agentkeys memory inbox-accept --s3-key <s3_key> --confirm-content-hash {content_hash}"
        ),
        "persona" => "\n\npersona proposals are never inbox-adoptable (master-authored only) — \
             reject it and edit the persona in parent-control (#390)."
            .to_string(),
        _ => String::new(),
    };
    Ok(format!(
        "proposal: memory:{ns} / {key} · kind {kind}\n  \
         from delegate: {from} (worker-stamped provenance)\n  \
         content_hash: {content_hash}\n  \
         ts: {ts}\n\n\
         --- body ---\n{body}\n------------{accept_hint}"
    ))
}

/// `agentkeys memory inbox-accept --s3-key …` → daemon `POST /v1/master/inbox/accept`.
/// Curates the proposal INTO canonical memory (the daemon's per-namespace MERGE
/// plant) then GCs the inbox object. This is the master's pull-request "merge" —
/// the delegate never wrote canonical directly.
/// #390 — `confirm_content_hash` is the viewed-body watermark REQUIRED for
/// `skill` proposals (the hash `inbox-view` prints); the daemon's per-kind gate
/// rejects a skill accept without it, and rejects `persona` accepts outright.
pub async fn inbox_accept(
    daemon_url: &str,
    s3_key: &str,
    confirm_content_hash: Option<&str>,
) -> Result<String> {
    let url = format!(
        "{}/v1/master/inbox/accept",
        daemon_url.trim_end_matches('/')
    );
    let mut body = json!({ "s3_key": s3_key });
    if let Some(hash) = confirm_content_hash {
        body["confirm_content_hash"] = json!(hash);
    }
    let value = daemon_call(reqwest::Method::POST, &url, Some(body)).await?;
    let ns = value.get("ns").and_then(Value::as_str).unwrap_or("?");
    let key = value.get("key").and_then(Value::as_str).unwrap_or("?");
    let planted = value.get("planted").and_then(Value::as_u64).unwrap_or(0);
    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
    if !ok {
        // The merge committed but the inbox GC failed — surface it, don't claim a clean accept.
        let err = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("(unspecified)");
        return Ok(format!(
            "curated memory:{ns} / {key} into canonical (planted {planted}), but the inbox \
             object was NOT GC'd: {err}\n  \
             re-run: agentkeys memory inbox-reject --s3-key {s3_key} to clear it."
        ));
    }
    Ok(format!(
        "accepted — curated memory:{ns} / {key} into canonical memory (planted {planted}); \
         inbox proposal GC'd."
    ))
}

/// `agentkeys memory inbox-reject --s3-key …` → daemon `POST /v1/master/inbox/reject`.
/// Discards the proposal (GC the inbox object); canonical memory is untouched.
pub async fn inbox_reject(daemon_url: &str, s3_key: &str) -> Result<String> {
    let url = format!(
        "{}/v1/master/inbox/reject",
        daemon_url.trim_end_matches('/')
    );
    daemon_call(
        reqwest::Method::POST,
        &url,
        Some(json!({ "s3_key": s3_key })),
    )
    .await?;
    Ok(format!(
        "rejected — proposal discarded from the inbox (canonical memory untouched).\n  s3_key: {s3_key}"
    ))
}
