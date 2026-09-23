//! #664 — `agentkeys app install|list|uninstall` + `agentkeys resource
//! add|list`: the HEADLESS twins of the parent-control Applications page
//! (epic #660). Thin clients of the master daemon's ui-bridge routes — the
//! ONE implementation of the install / uninstall ceremonies lives in the
//! daemon (`apps.rs`); the CLI adds only the software-passkey signature for
//! the Touch-ID step (CI / headless / throwaway-TEST masters ONLY, the #164
//! posture — a real operator installs from the console).

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use agentkeys_backend_client::protocol::{
    AppInstallBindings, ContactTier, ResourceBinding, ResourceKind, Sensitivity, SlotAudience,
    SlotBinding,
};

pub const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:3114";

fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .build()
        .context("build http client")
}

async fn daemon_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    daemon_url: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let url = format!("{}{}", daemon_url.trim_end_matches('/'), path);
    let mut req = client.request(method.clone(), &url);
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("{method} {path} (is the daemon up at {daemon_url}?)"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("{method} {path} failed: HTTP {status}: {text}");
    }
    serde_json::from_str(&text).with_context(|| format!("parse {path}: {text}"))
}

/// Parse `slot=channel[,slot=channel...]` binding specs.
pub fn parse_slot_bindings(spec: &str) -> Result<Vec<SlotBinding>> {
    let mut out = Vec::new();
    for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (slot, channel) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("--bind expects slot=channel-id, got `{pair}`"))?;
        out.push(SlotBinding {
            slot: slot.trim().to_string(),
            channel_id: channel.trim().to_string(),
            endpoint_actor_omni: None,
        });
    }
    Ok(out)
}

/// Parse `name=item-id[,...]` resource specs (the daemon resolves ns / kind /
/// sensitivity from the registry).
pub fn parse_resource_bindings(spec: &str) -> Result<Vec<ResourceBinding>> {
    let mut out = Vec::new();
    for pair in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, item) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("--resource expects name=item-id, got `{pair}`"))?;
        out.push(ResourceBinding {
            name: name.trim().to_string(),
            item_id: item.trim().to_string(),
            ns: String::new(),
            kind: ResourceKind::Document,
            sensitivity: Sensitivity::Safe,
        });
    }
    Ok(out)
}

/// Parse `slot=tier|tier[;slot=...]` audience overrides.
pub fn parse_audience(spec: &str) -> Result<Vec<SlotAudience>> {
    let mut out = Vec::new();
    for pair in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (slot, tiers) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("--audience expects slot=tier|tier, got `{pair}`"))?;
        let mut parsed = Vec::new();
        for t in tiers.split('|').map(str::trim).filter(|t| !t.is_empty()) {
            parsed.push(
                ContactTier::parse(t)
                    .ok_or_else(|| anyhow!("unknown household tier `{t}` in --audience"))?,
            );
        }
        out.push(SlotAudience {
            slot: slot.trim().to_string(),
            tiers: parsed,
        });
    }
    Ok(out)
}

/// `agentkeys app install` — build → software-sign → submit against the daemon.
#[allow(clippy::too_many_arguments)]
pub async fn app_install(
    daemon_url: &str,
    template: &str,
    label: &str,
    bind: &str,
    resources: &str,
    audience: &str,
    tz_offset_minutes: i32,
    enroll_endpoints: bool,
    k11_key_file: &str,
    rp_id: &str,
) -> Result<String> {
    let bindings = AppInstallBindings {
        slots: parse_slot_bindings(bind)?,
        resources: parse_resource_bindings(resources)?,
        audience: parse_audience(audience)?,
        tz_offset_minutes,
    };
    let client = client()?;
    let built = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        "/v1/master/apps/install/build",
        Some(&json!({ "template_id": template, "label": label, "bindings": bindings, "enroll_endpoints": enroll_endpoints })),
    )
    .await?;
    let build = built
        .get("build")
        .cloned()
        .ok_or_else(|| anyhow!("install/build returned no `build` envelope: {built}"))?;
    let user_op_hash = build
        .get("user_op_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("install/build carried no user_op_hash"))?;
    let assertion = crate::agent_admin::software_assertion(k11_key_file, user_op_hash, rp_id)?;
    let submit_body = json!({ "user_op": build.get("user_op"), "assertion": assertion });
    let submitted = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        "/v1/master/apps/install/submit",
        Some(&submit_body),
    )
    .await?;
    let out = json!({
        "outcome": "installed",
        "label": label,
        "template_id": built.get("template_id"),
        "template_version": built.get("template_version"),
        "services": build.get("services"),
        "annotations": build.get("annotations"),
        "bound_channels": build.get("bound_channels"),
        "audience": build.get("audience"),
        "endpoint_scopes": built.get("endpoint_scopes"),
        "endpoint_enrollments": built.get("endpoint_enrollments"),
        "context_seal": build.get("context_seal"),
        "actor_omni": build.get("actor_omni"),
        "device_key_hash": build.get("device_key_hash"),
        "tx_hash": submitted.get("tx_hash"),
        "installed": submitted.get("installed"),
        "ceremony": submitted.get("ceremony"),
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// `agentkeys app rebind` (#717) — change an INSTALLED app's channel slots in
/// place: build → ONE software-passkey signature → submit. A commit, not a
/// reinstall: no uninstall, no delegate slot consumed; the daemon updates the
/// registry row, the gate's `alias → channel`, the broker's spawn context and
/// re-sources the live runtime.
pub async fn app_rebind(
    daemon_url: &str,
    label: &str,
    bind: &str,
    enroll_endpoints: bool,
    k11_key_file: &str,
    rp_id: &str,
) -> Result<String> {
    let slots = parse_slot_bindings(bind)?;
    if slots.is_empty() {
        anyhow::bail!("--bind names no slot (slot=channel-id[,slot=channel-id…])");
    }
    let client = client()?;
    let built = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        &format!("/v1/master/apps/{label}/rebind/build"),
        Some(&json!({ "slots": slots, "enroll_endpoints": enroll_endpoints })),
    )
    .await?;
    let build = built
        .get("build")
        .cloned()
        .ok_or_else(|| anyhow!("rebind/build returned no `build` envelope: {built}"))?;
    let user_op_hash = build
        .get("user_op_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("rebind/build carried no user_op_hash"))?;
    let assertion = crate::agent_admin::software_assertion(k11_key_file, user_op_hash, rp_id)?;
    let submit_body = json!({ "user_op": build.get("user_op"), "assertion": assertion });
    let submitted = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        &format!("/v1/master/apps/{label}/rebind/submit"),
        Some(&submit_body),
    )
    .await?;
    let out = json!({
        "outcome": "rebound",
        "label": label,
        "changes": built.get("changes"),
        "services": built.get("services"),
        "bound_channels": built.get("bound_channels"),
        "endpoint_scopes": built.get("endpoint_scopes"),
        "endpoint_enrollments": built.get("endpoint_enrollments"),
        "context_seal": build.get("context_seal"),
        "tx_hash": submitted.get("tx_hash"),
        "rebound": submitted.get("rebound"),
    });
    Ok(serde_json::to_string_pretty(&out)?)
}

/// `agentkeys app list`
pub async fn app_list(daemon_url: &str) -> Result<String> {
    let v = daemon_json(
        &client()?,
        reqwest::Method::GET,
        daemon_url,
        "/v1/master/apps",
        None,
    )
    .await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys app show <label>` — the dashboard read.
pub async fn app_show(daemon_url: &str, label: &str) -> Result<String> {
    let v = daemon_json(
        &client()?,
        reqwest::Method::GET,
        daemon_url,
        &format!("/v1/master/apps/{label}"),
        None,
    )
    .await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys app uninstall` — build → software-sign → submit.
pub async fn app_uninstall(
    daemon_url: &str,
    label: &str,
    keep_memory: bool,
    k11_key_file: &str,
    rp_id: &str,
) -> Result<String> {
    let client = client()?;
    let built = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        &format!("/v1/master/apps/{label}/uninstall/build"),
        Some(&json!({ "resources_kept": keep_memory })),
    )
    .await?;
    let user_op_hash = built
        .get("user_op_hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| anyhow!("uninstall/build carried no user_op_hash: {built}"))?;
    let assertion = crate::agent_admin::software_assertion(k11_key_file, user_op_hash, rp_id)?;
    let submitted = daemon_json(
        &client,
        reqwest::Method::POST,
        daemon_url,
        &format!("/v1/master/apps/{label}/uninstall/submit"),
        Some(&json!({ "user_op": built.get("user_op"), "assertion": assertion })),
    )
    .await?;
    Ok(serde_json::to_string_pretty(&json!({
        "outcome": "uninstalled",
        "label": label,
        "resources_kept": keep_memory,
        "tx_hash": submitted.get("tx_hash"),
        "uninstalled": submitted.get("uninstalled"),
        "ceremony": submitted.get("ceremony"),
    }))?)
}

/// `agentkeys app command <label>` — a card action tap, headless.
pub async fn app_command(
    daemon_url: &str,
    label: &str,
    action: &str,
    command: &str,
    args: &str,
) -> Result<String> {
    let args_v: Value = if args.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(args).context("--args must be JSON")?
    };
    let v = daemon_json(
        &client()?,
        reqwest::Method::POST,
        daemon_url,
        &format!("/v1/master/apps/{label}/command"),
        Some(&json!({ "action": action, "command": command, "args": args_v })),
    )
    .await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys resource add`
#[allow(clippy::too_many_arguments)]
pub async fn resource_add(
    daemon_url: &str,
    id: &str,
    name: &str,
    name_zh: &str,
    kind: &str,
    tags: &str,
    sensitivity: &str,
    ns: &str,
    body: String,
) -> Result<String> {
    let kind = ResourceKind::parse(kind)
        .ok_or_else(|| anyhow!("--kind must be document|profile|dataset|gallery"))?;
    let sensitivity = match sensitivity.trim().to_ascii_lowercase().as_str() {
        "safe" => Sensitivity::Safe,
        "sensitive" => Sensitivity::Sensitive,
        other => bail!("--sensitivity must be safe|sensitive (got `{other}`)"),
    };
    let tags: Vec<String> = tags
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    let v = daemon_json(
        &client()?,
        reqwest::Method::POST,
        daemon_url,
        "/v1/master/resources/add",
        Some(&json!({
            "id": id, "name": name, "name_zh": name_zh, "kind": kind, "tags": tags,
            "sensitivity": sensitivity, "ns": ns, "body": body,
        })),
    )
    .await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

/// `agentkeys resource list`
pub async fn resource_list(daemon_url: &str) -> Result<String> {
    let v = daemon_json(
        &client()?,
        reqwest::Method::GET,
        daemon_url,
        "/v1/master/resources",
        None,
    )
    .await?;
    Ok(serde_json::to_string_pretty(&v)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_specs_parse() {
        let s = parse_slot_bindings("family_chat=weixin, kitchen_screen=kitchen-display").unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[1].slot, "kitchen_screen");
        assert_eq!(s[1].channel_id, "kitchen-display");
        assert!(parse_slot_bindings("nope").is_err());
        let r = parse_resource_bindings("food-preferences=prefs-1").unwrap();
        assert_eq!(r[0].item_id, "prefs-1");
        let a = parse_audience("family_chat=owner|partner;other=kid").unwrap();
        assert_eq!(a[0].tiers, vec![ContactTier::Owner, ContactTier::Partner]);
        assert_eq!(a[1].tiers, vec![ContactTier::Kid]);
        assert!(parse_audience("family_chat=alien").is_err());
        assert!(parse_slot_bindings("").unwrap().is_empty());
    }
}
