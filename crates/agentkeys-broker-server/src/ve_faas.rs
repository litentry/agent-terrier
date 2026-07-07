//! Broker-driven veFaaS sandbox lifecycle (issue #377) — one hermes-sandbox
//! instance per delegate device, spawned/extended/killed by the broker on the
//! delegation/pairing lifecycle. veFaaS OpenAPI on the SAME [`ve_sign`]
//! Signature V4 signer as [`ve_sts`](crate::ve_sts) (`service = "vefaas"`,
//! `Version = 2024-06-06` — the contract proven live by
//! `crates/agentkeys-volcano-probe/src/sandbox.rs` and
//! `docs/hardware/volcano/service.md` §1):
//!
//! | Action              | use here                                        |
//! |---------------------|--------------------------------------------------|
//! | `CreateSandbox`     | spawn the delegate's instance (labeled)          |
//! | `ListSandboxes`     | find the delegate's live instance (quota ≤ 1)    |
//! | `DescribeSandbox`   | status probe (live test / diagnostics)           |
//! | `SetSandboxTimeout` | extend an active delegate's instance on resolve  |
//! | `KillSandbox`       | teardown on unpair                               |
//!
//! ## Per-delegate quota invariant
//!
//! `CreateSandbox` is append-only (no server-side upsert), so idempotency is
//! enforced HERE: every broker-spawned instance carries `Metadata` labels
//! keyed on the delegate identity ([`LABEL_DEVICE_KEY_HASH`]), `ensure`
//! serializes spawns behind one lock, reuses any live labeled instance, and
//! refuses to create past [`VeFaasConfig::max_instances`] (spawn-storm
//! backstop). Matching is CLIENT-SIDE on the returned rows' `Metadata` (the
//! request also passes the server-side `Metadata` filter documented in
//! service.md §1 — belt and braces); after a create, `ensure` re-lists and
//! ERRORs loudly if the labels are not visible, because then the quota
//! invariant is unenforceable — never silently (no-silent-fallback policy).
//! `tests/ve_faas_live.rs` pins the real API behavior.
//!
//! ## Routing (#395 deferral)
//!
//! Per-delegate request ROUTING is not implemented yet — devices POST the
//! shared gateway URL headerless and reach a random Ready instance
//! (`docs/hardware/volcano/ve-deployment.md`). The labels stamped here are
//! exactly what that follow-up consumes (`x-faas-instance-name: <SandboxId>`).

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};

use crate::ve_sign::{self, VeSignRequest};

/// veFaaS OpenAPI constants (proven live by the volcano-probe).
pub const DEFAULT_VEFAAS_HOST: &str = "open.volcengineapi.com";
pub const VEFAAS_SERVICE: &str = "vefaas";
pub const VEFAAS_VERSION: &str = "2024-06-06";

/// `Metadata` label carrying the delegate's `device_key_hash` — THE
/// per-delegate quota key (and the handle #395 routing will consume).
pub const LABEL_DEVICE_KEY_HASH: &str = "agentkeys_device_key_hash";
/// `Metadata` label carrying the delegate's actor omni (diagnostics).
pub const LABEL_ACTOR_OMNI: &str = "agentkeys_actor_omni";
/// Marks instances this broker manages; `kill_for_device` refuses to touch
/// anything without it (an operator's hand-spawned instance is never ours).
pub const LABEL_MANAGED_BY: &str = "agentkeys_managed_by";
pub const MANAGED_BY_VALUE: &str = "broker";

/// Instance statuses that count as "the delegate already has a sandbox" —
/// reuse, never duplicate. `Paused` is veFaaS hibernation (wakes on traffic).
const LIVE_STATUSES: &[&str] = &["ready", "running", "starting", "paused"];

/// Sandbox-lifecycle config, read ONCE at boot (never re-read env later —
/// tests inject via [`VeFaasConfig::from_lookup`], the #258 posture).
#[derive(Debug, Clone)]
pub struct VeFaasConfig {
    /// The sandbox application (`SANDBOX_FUNCTION_ID`, config.md §4) —
    /// presence of this key is what ENABLES broker-driven spawn.
    pub function_id: String,
    /// The devices' agent base URL (`SANDBOX_GATEWAY_URL`, config.md §5),
    /// returned as `agent_url` on resolve. Trailing `/` trimmed so the
    /// device's `POST <url>/v1/chat` never doubles the slash.
    pub gateway_url: String,
    /// Hermes image in Volcano CR (`CR_IMAGE`, ve-deployment.md §2). Empty =
    /// spawn on the sandbox application's console-configured image.
    pub image: String,
    /// Instance exposed port = the gateway's default proxy target
    /// (`AGENTKEYS_VEFAAS_PORT`, default 8090 — the hermes bridge).
    pub port: u32,
    /// Instance command (`AGENTKEYS_VEFAAS_COMMAND`, default `/opt/gem/run.sh`
    /// — the base-image entrypoint, same default as spawn-vefaas.sh).
    pub command: String,
    /// Instance lifetime in minutes (`AGENTKEYS_VEFAAS_TIMEOUT_MINUTES`,
    /// default 1440; veFaaS bounds are 3–1440). Also the amount each resolve
    /// re-extends by, so an ACTIVE device's sandbox never expires while an
    /// abandoned one dies within this window.
    pub timeout_minutes: u32,
    /// Refuse to create past this many instances under the application
    /// (`AGENTKEYS_VEFAAS_MAX_INSTANCES`, default 20) — bounds the blast
    /// radius if label matching ever breaks (see module docs).
    pub max_instances: usize,
    pub host: String,
    pub region: String,
}

impl VeFaasConfig {
    /// Build from a lookup fn (`None` = unset). Returns `Ok(None)` when the
    /// feature is disabled (no `SANDBOX_FUNCTION_ID`); `Err` on a half-set
    /// config — never a silently degraded one.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>> {
        let non_empty = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let Some(function_id) = non_empty("SANDBOX_FUNCTION_ID") else {
            return Ok(None);
        };
        let gateway_url = non_empty("SANDBOX_GATEWAY_URL")
            .ok_or_else(|| {
                anyhow!(
                    "SANDBOX_FUNCTION_ID is set but SANDBOX_GATEWAY_URL is not — the broker \
                     cannot hand devices an agent_url. Set both (docs/hardware/volcano/config.md) \
                     or neither."
                )
            })?
            .trim_end_matches('/')
            .to_string();
        let parse_u32 = |k: &str, default: u32| -> Result<u32> {
            match non_empty(k) {
                Some(v) => v
                    .parse::<u32>()
                    .with_context(|| format!("{k}={v:?} not a u32")),
                None => Ok(default),
            }
        };
        let timeout_minutes = parse_u32("AGENTKEYS_VEFAAS_TIMEOUT_MINUTES", 1440)?;
        if !(3..=1440).contains(&timeout_minutes) {
            bail!("AGENTKEYS_VEFAAS_TIMEOUT_MINUTES must be 3..=1440 (veFaaS bound), got {timeout_minutes}");
        }
        Ok(Some(Self {
            function_id,
            gateway_url,
            image: non_empty("CR_IMAGE").unwrap_or_default(),
            port: parse_u32("AGENTKEYS_VEFAAS_PORT", 8090)?,
            command: non_empty("AGENTKEYS_VEFAAS_COMMAND")
                .unwrap_or_else(|| "/opt/gem/run.sh".to_string()),
            timeout_minutes,
            max_instances: parse_u32("AGENTKEYS_VEFAAS_MAX_INSTANCES", 20)? as usize,
            host: non_empty("AGENTKEYS_VEFAAS_HOST")
                .unwrap_or_else(|| DEFAULT_VEFAAS_HOST.to_string()),
            region: non_empty("VOLCENGINE_REGION").unwrap_or_else(|| "cn-beijing".to_string()),
        }))
    }
}

/// One instance row from `ListSandboxes` (+ its labels when the API returns
/// them — `tests/ve_faas_live.rs` pins that it does).
#[derive(Debug, Clone)]
pub struct SandboxInstance {
    pub id: String,
    pub status: String,
    pub expire_at: String,
    pub metadata: HashMap<String, String>,
}

impl SandboxInstance {
    pub fn is_live(&self) -> bool {
        let s = self.status.to_ascii_lowercase();
        LIVE_STATUSES.iter().any(|l| *l == s)
    }

    fn labeled_for(&self, device_key_hash: &str) -> bool {
        self.metadata
            .get(LABEL_DEVICE_KEY_HASH)
            .is_some_and(|v| v.eq_ignore_ascii_case(device_key_hash))
            && self
                .metadata
                .get(LABEL_MANAGED_BY)
                .is_some_and(|v| v == MANAGED_BY_VALUE)
    }
}

/// Outcome of [`VeFaasClient::ensure_for_delegate`].
#[derive(Debug, Clone)]
pub struct EnsureOutcome {
    pub sandbox_id: String,
    /// `true` when this call actually created the instance (the audit-emit
    /// trigger); `false` when a live labeled instance was reused.
    pub created: bool,
    pub status: String,
}

/// The broker's veFaaS client. Holds the SAME VE identity as
/// [`ve_sts`](crate::ve_sts) (`VOLCENGINE_ACCESS_KEY`/`_SECRET_KEY`), scoped
/// on the cloud side to ONLY the five lifecycle actions
/// (`setup-cloud-ve.sh` step 15 / `policies/ve-broker-vefaas.json`, the #372
/// posture). No Debug impl — a derived one would render the secret key.
pub struct VeFaasClient {
    http: reqwest::Client,
    access_key_id: String,
    secret_access_key: String,
    pub config: VeFaasConfig,
    /// The delegate instances' Ark env rides the #338 isolated ark family
    /// (`AGENTKEYS_INFERENCE_CREDS_DIR`), resolved per spawn so a rotation
    /// lands without a broker restart.
    inference: agentkeys_inference_creds::Resolver,
    /// Optional web-search model forwarded to instances (`SEARCH_MODEL`).
    search_model: Option<String>,
    /// Spawns are serialized so two concurrent resolves for the same (or
    /// different) delegates can't race list→create into duplicates. Spawn is
    /// a rare event (pair / device boot); one lock is simpler than a
    /// per-device map and the contention is irrelevant at this rate.
    ensure_lock: tokio::sync::Mutex<()>,
}

impl VeFaasClient {
    /// Construct from the environment — read ONCE here, never re-read later.
    /// Returns `Ok(None)` when the sandbox lifecycle is not configured (the
    /// AWS broker host, or a VE host predating #377).
    ///
    ///   SANDBOX_FUNCTION_ID                the sandbox application (enables the feature)
    ///   SANDBOX_GATEWAY_URL                devices' agent base URL (required with the above)
    ///   CR_IMAGE                           hermes image in Volcano CR (empty = app default)
    ///   AGENTKEYS_VEFAAS_PORT              default 8090
    ///   AGENTKEYS_VEFAAS_COMMAND           default /opt/gem/run.sh
    ///   AGENTKEYS_VEFAAS_TIMEOUT_MINUTES   default 1440 (3..=1440)
    ///   AGENTKEYS_VEFAAS_MAX_INSTANCES     default 20
    ///   AGENTKEYS_VEFAAS_HOST              default open.volcengineapi.com
    ///   VOLCENGINE_ACCESS_KEY / _SECRET_KEY  broker VE identity (required with the above)
    ///   VOLCENGINE_REGION                  default cn-beijing
    ///   SEARCH_MODEL                       optional, forwarded to instances
    ///   AGENTKEYS_INFERENCE_CREDS_DIR      ark-family file dir (#338 loader)
    pub fn from_env() -> Result<Option<Self>> {
        let get = |k: &str| std::env::var(k).ok();
        let Some(config) = VeFaasConfig::from_lookup(get)? else {
            return Ok(None);
        };
        let ak = std::env::var("VOLCENGINE_ACCESS_KEY").unwrap_or_default();
        let sk = std::env::var("VOLCENGINE_SECRET_KEY").unwrap_or_default();
        if ak.is_empty() || sk.is_empty() {
            bail!(
                "SANDBOX_FUNCTION_ID is set but VOLCENGINE_ACCESS_KEY/_SECRET_KEY are not — \
                 the broker cannot sign veFaaS lifecycle calls. Provide the broker VE identity \
                 (the same one ve_sts uses) or unset SANDBOX_FUNCTION_ID."
            );
        }
        Ok(Some(Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .connect_timeout(std::time::Duration::from_secs(5))
                .build()
                .context("build veFaaS http client")?,
            access_key_id: ak,
            secret_access_key: sk,
            config,
            inference: agentkeys_inference_creds::Resolver::from_process(),
            search_model: std::env::var("SEARCH_MODEL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            ensure_lock: tokio::sync::Mutex::new(()),
        }))
    }

    /// The base URL devices talk to (`agent_url` in the resolve response).
    pub fn agent_url(&self) -> &str {
        &self.config.gateway_url
    }

    /// V4-sign + POST one veFaaS action; surfaces the VE `{Code, Message}`
    /// error pair on failure (any HTTP status).
    async fn vefaas_call(
        &self,
        action: &str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let body_str = serde_json::to_string(&body)?;
        let query = ve_sign::canonical_query(&[("Action", action), ("Version", VEFAAS_VERSION)]);
        let x_date = ve_sign::now_x_date();
        let signed = ve_sign::sign(&VeSignRequest {
            access_key_id: &self.access_key_id,
            secret_access_key: &self.secret_access_key,
            session_token: None,
            region: &self.config.region,
            service: VEFAAS_SERVICE,
            host: &self.config.host,
            method: "POST",
            path: "/",
            query: &query,
            body: body_str.as_bytes(),
            content_type: "application/json",
            x_date: &x_date,
        });
        let url = format!("https://{}/?{}", self.config.host, query);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", &signed.content_type)
            .header("X-Date", &signed.x_date)
            .header("X-Content-Sha256", &signed.x_content_sha256)
            .header("Authorization", &signed.authorization)
            .body(body_str)
            .send()
            .await
            .with_context(|| format!("vefaas {action} request failed"))?;
        let status = resp.status();
        let v: serde_json::Value = resp
            .json()
            .await
            .with_context(|| format!("vefaas {action} response was not JSON (http {status})"))?;
        if v["ResponseMetadata"]["Error"].is_object() {
            let err = &v["ResponseMetadata"]["Error"];
            bail!(
                "vefaas {action} error (http {status}): Code={} Message={}",
                err["Code"].as_str().unwrap_or("?"),
                err["Message"].as_str().unwrap_or("?")
            );
        }
        Ok(v)
    }

    /// `ListSandboxes` under the configured application. `label_filter` is
    /// ALSO passed server-side (service.md §1 documents a `Metadata` filter);
    /// callers still match client-side on the rows' labels.
    pub async fn list_instances(
        &self,
        label_filter: Option<&[(&str, &str)]>,
    ) -> Result<Vec<SandboxInstance>> {
        let mut body = serde_json::json!({
            "FunctionId": self.config.function_id,
            "PageSize": 100,
        });
        if let Some(labels) = label_filter {
            body["Metadata"] = label_map(labels);
        }
        let v = self.vefaas_call("ListSandboxes", body).await?;
        Ok(parse_instances(&v))
    }

    /// `DescribeSandbox` → `(status, expire_at)` for one instance.
    pub async fn describe(&self, sandbox_id: &str) -> Result<(String, String)> {
        let v = self
            .vefaas_call(
                "DescribeSandbox",
                serde_json::json!({
                    "FunctionId": self.config.function_id,
                    "SandboxId": sandbox_id,
                }),
            )
            .await?;
        Ok((
            v["Result"]["Status"].as_str().unwrap_or("?").to_string(),
            v["Result"]["ExpireAt"].as_str().unwrap_or("?").to_string(),
        ))
    }

    /// `KillSandbox` one instance.
    pub async fn kill(&self, sandbox_id: &str) -> Result<()> {
        self.vefaas_call(
            "KillSandbox",
            serde_json::json!({
                "FunctionId": self.config.function_id,
                "SandboxId": sandbox_id,
            }),
        )
        .await?;
        Ok(())
    }

    /// `SetSandboxTimeout` — reset the instance's remaining lifetime to
    /// `timeout_minutes` (the resolve-time keep-alive).
    pub async fn extend(&self, sandbox_id: &str) -> Result<()> {
        self.vefaas_call(
            "SetSandboxTimeout",
            serde_json::json!({
                "FunctionId": self.config.function_id,
                "SandboxId": sandbox_id,
                "Timeout": self.config.timeout_minutes,
            }),
        )
        .await?;
        Ok(())
    }

    /// The instance env for a delegate's hermes-sandbox: the #338 ark family
    /// (resolved NOW so rotations apply) + the optional search model. A
    /// missing ark family is a HARD error with the rotation command — an
    /// instance without an LLM key would boot broken in a way the device
    /// can't diagnose.
    fn instance_envs(&self) -> Result<Vec<(String, String)>> {
        let ark = self.inference.ark().map_err(|e| {
            anyhow!(
                "cannot spawn a delegate sandbox: the ark inference family does not resolve \
                 ({e}). Populate it with: AGENTKEYS_INFERENCE_CREDS_DIR=<dir> \
                 bash scripts/operator/secrets/rotate-inference-cred.sh ark"
            )
        })?;
        let mut envs = vec![
            ("ARK_API_KEY".to_string(), ark.api_key),
            ("LLM_ENDPOINT_ID".to_string(), ark.endpoint_id),
            ("ARK_BASE_URL".to_string(), ark.base_url),
        ];
        if let Some(m) = &self.search_model {
            envs.push(("SEARCH_MODEL".to_string(), m.clone()));
        }
        Ok(envs)
    }

    /// `CreateSandbox` labeled for the delegate → the new `SandboxId`.
    async fn create_for_delegate(&self, device_key_hash: &str, actor_omni: &str) -> Result<String> {
        let mut body = serde_json::json!({
            "FunctionId": self.config.function_id,
            "Timeout": self.config.timeout_minutes,
            "Metadata": label_map(&delegate_labels(device_key_hash, actor_omni)),
        });
        let envs: Vec<serde_json::Value> = self
            .instance_envs()?
            .into_iter()
            .map(|(k, v)| serde_json::json!({ "Key": k, "Value": v }))
            .collect();
        body["Envs"] = serde_json::json!(envs);
        if !self.config.image.is_empty() {
            body["InstanceImageInfo"] = serde_json::json!({
                "Image": self.config.image,
                "Port": self.config.port,
                "Command": self.config.command,
            });
        }
        let v = self.vefaas_call("CreateSandbox", body).await?;
        let id = v["Result"]["SandboxId"].as_str().unwrap_or_default();
        if id.is_empty() {
            bail!("CreateSandbox returned no Result.SandboxId: {v}");
        }
        Ok(id.to_string())
    }

    /// THE #377 entry point: give the delegate its runtime, idempotently.
    /// Reuses the delegate's live labeled instance (extending its lifetime),
    /// else creates one; at most ONE live instance per delegate ever exists.
    pub async fn ensure_for_delegate(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
    ) -> Result<EnsureOutcome> {
        let _guard = self.ensure_lock.lock().await;

        let all = self.list_instances(None).await?;
        if let Some(mine) = pick_live_for_device(&all, device_key_hash) {
            // Keep an ACTIVE delegate's runtime alive; an extend failure is a
            // WARN, not a spawn failure — the instance still lives until its
            // current expiry.
            if let Err(e) = self.extend(&mine.id).await {
                tracing::warn!(sandbox_id = %mine.id, error = %e, "veFaaS SetSandboxTimeout failed — instance keeps its current expiry");
            }
            return Ok(EnsureOutcome {
                sandbox_id: mine.id.clone(),
                created: false,
                status: mine.status.clone(),
            });
        }

        let live_total = all.iter().filter(|i| i.is_live()).count();
        if live_total >= self.config.max_instances {
            bail!(
                "refusing to spawn: {live_total} live instances under {} >= AGENTKEYS_VEFAAS_MAX_INSTANCES ({}) — \
                 if label matching is broken this cap is what bounds the damage; inspect `ListSandboxes`",
                self.config.function_id,
                self.config.max_instances
            );
        }

        let id = self
            .create_for_delegate(device_key_hash, actor_omni)
            .await?;

        // Quota-invariant self-check: the fresh instance must be findable by
        // its label, or every future ensure() will duplicate it. Loud ERROR,
        // never silent (tests/ve_faas_live.rs pins that this holds on real VE).
        let relisted = self
            .list_instances(Some(&delegate_labels(device_key_hash, actor_omni)))
            .await
            .unwrap_or_default();
        if !relisted
            .iter()
            .any(|i| i.id == id && i.labeled_for(device_key_hash))
        {
            tracing::error!(
                sandbox_id = %id,
                device_key_hash = %device_key_hash,
                "veFaaS Metadata labels NOT visible on ListSandboxes rows — the per-delegate \
                 quota invariant (#377) is UNENFORCEABLE and future ensures will duplicate \
                 instances until the cap. Run tests/ve_faas_live.rs and fix the label plumbing."
            );
        }

        let status = self
            .describe(&id)
            .await
            .map(|(s, _)| s)
            .unwrap_or_else(|_| "Starting".to_string());
        Ok(EnsureOutcome {
            sandbox_id: id,
            created: true,
            status,
        })
    }

    /// Teardown on unpair: kill every live broker-managed instance labeled
    /// for the device. Returns the killed ids (empty when the delegate had no
    /// runtime — a valid no-op, e.g. a device revoked before ever resolving).
    pub async fn kill_for_device(&self, device_key_hash: &str) -> Result<Vec<String>> {
        let all = self
            .list_instances(Some(&[(LABEL_DEVICE_KEY_HASH, device_key_hash)]))
            .await?;
        let mut killed = Vec::new();
        for inst in all
            .iter()
            .filter(|i| i.labeled_for(device_key_hash) && i.is_live())
        {
            self.kill(&inst.id)
                .await
                .with_context(|| format!("KillSandbox {}", inst.id))?;
            killed.push(inst.id.clone());
        }
        Ok(killed)
    }
}

/// The labels stamped on a delegate's instance.
fn delegate_labels<'a>(
    device_key_hash: &'a str,
    actor_omni: &'a str,
) -> [(&'static str, &'a str); 3] {
    [
        (LABEL_DEVICE_KEY_HASH, device_key_hash),
        (LABEL_ACTOR_OMNI, actor_omni),
        (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
    ]
}

fn label_map(labels: &[(&str, &str)]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in labels {
        m.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    serde_json::Value::Object(m)
}

/// Parse `Result.Sandboxes[]` rows. Field names per the probe's proven
/// parser (`Id`/`Status`/`ExpireAt`); `Metadata` accepted as either a string
/// map or a `[{Key,Value}]` list (the two shapes VE APIs use for maps).
fn parse_instances(v: &serde_json::Value) -> Vec<SandboxInstance> {
    let Some(list) = v["Result"]["Sandboxes"].as_array() else {
        return Vec::new();
    };
    list.iter()
        .map(|s| SandboxInstance {
            id: s["Id"].as_str().unwrap_or_default().to_string(),
            status: s["Status"].as_str().unwrap_or_default().to_string(),
            expire_at: s["ExpireAt"].as_str().unwrap_or_default().to_string(),
            metadata: parse_metadata(&s["Metadata"]),
        })
        .collect()
}

fn parse_metadata(v: &serde_json::Value) -> HashMap<String, String> {
    let mut out = HashMap::new();
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    out.insert(k.clone(), s.to_string());
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let (Some(k), Some(val)) = (item["Key"].as_str(), item["Value"].as_str()) {
                    out.insert(k.to_string(), val.to_string());
                }
            }
        }
        _ => {}
    }
    out
}

/// Pure quota decision: the delegate's live instance among `rows`, if any.
fn pick_live_for_device<'a>(
    rows: &'a [SandboxInstance],
    device_key_hash: &str,
) -> Option<&'a SandboxInstance> {
    rows.iter()
        .find(|i| i.is_live() && i.labeled_for(device_key_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_lookup<'a>(map: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| {
            map.iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn config_absent_function_id_disables_feature() {
        let cfg = VeFaasConfig::from_lookup(cfg_lookup(&[])).unwrap();
        assert!(cfg.is_none());
    }

    #[test]
    fn config_half_set_is_a_hard_error() {
        let err = VeFaasConfig::from_lookup(cfg_lookup(&[("SANDBOX_FUNCTION_ID", "fn1")]))
            .err()
            .unwrap();
        assert!(err.to_string().contains("SANDBOX_GATEWAY_URL"), "{err}");
    }

    #[test]
    fn config_defaults_and_gateway_slash_trim() {
        let cfg = VeFaasConfig::from_lookup(cfg_lookup(&[
            ("SANDBOX_FUNCTION_ID", "fn1"),
            ("SANDBOX_GATEWAY_URL", "https://gw.example/"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.gateway_url, "https://gw.example");
        assert_eq!(cfg.port, 8090);
        assert_eq!(cfg.command, "/opt/gem/run.sh");
        assert_eq!(cfg.timeout_minutes, 1440);
        assert_eq!(cfg.max_instances, 20);
        assert_eq!(cfg.host, DEFAULT_VEFAAS_HOST);
        assert_eq!(cfg.region, "cn-beijing");
        assert!(cfg.image.is_empty());
    }

    #[test]
    fn config_rejects_out_of_bound_timeout() {
        let err = VeFaasConfig::from_lookup(cfg_lookup(&[
            ("SANDBOX_FUNCTION_ID", "fn1"),
            ("SANDBOX_GATEWAY_URL", "https://gw.example"),
            ("AGENTKEYS_VEFAAS_TIMEOUT_MINUTES", "2000"),
        ]))
        .err()
        .unwrap();
        assert!(err.to_string().contains("3..=1440"), "{err}");
    }

    fn row(id: &str, status: &str, labels: &[(&str, &str)]) -> SandboxInstance {
        SandboxInstance {
            id: id.into(),
            status: status.into(),
            expire_at: String::new(),
            metadata: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn pick_live_matches_only_managed_labeled_live_rows() {
        let dev = "0xdev";
        let rows = vec![
            // right label, wrong status
            row(
                "dead",
                "Failed",
                &[
                    (LABEL_DEVICE_KEY_HASH, dev),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
            ),
            // live but a DIFFERENT device
            row(
                "other",
                "Ready",
                &[
                    (LABEL_DEVICE_KEY_HASH, "0xother"),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
            ),
            // live + labeled but NOT broker-managed (operator hand-spawn)
            row("manual", "Ready", &[(LABEL_DEVICE_KEY_HASH, dev)]),
            // live, no labels at all (stock instance)
            row("bare", "Ready", &[]),
            // the delegate's own
            row(
                "mine",
                "Ready",
                &[
                    (LABEL_DEVICE_KEY_HASH, dev),
                    (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
                ],
            ),
        ];
        assert_eq!(pick_live_for_device(&rows, dev).unwrap().id, "mine");
        assert!(pick_live_for_device(&rows, "0xnobody").is_none());
    }

    #[test]
    fn device_key_hash_match_is_case_insensitive_and_paused_counts_live() {
        let rows = vec![row(
            "hib",
            "Paused",
            &[
                (LABEL_DEVICE_KEY_HASH, "0xABCD"),
                (LABEL_MANAGED_BY, MANAGED_BY_VALUE),
            ],
        )];
        assert_eq!(pick_live_for_device(&rows, "0xabcd").unwrap().id, "hib");
    }

    #[test]
    fn parse_instances_reads_probe_shape_and_both_metadata_encodings() {
        let v = serde_json::json!({
            "Result": { "Sandboxes": [
                { "Id": "a", "Status": "Ready", "ExpireAt": "2026-07-06T00:00:00+08:00",
                  "Metadata": { LABEL_DEVICE_KEY_HASH: "0x11", LABEL_MANAGED_BY: MANAGED_BY_VALUE } },
                { "Id": "b", "Status": "Starting", "ExpireAt": "",
                  "Metadata": [ { "Key": LABEL_DEVICE_KEY_HASH, "Value": "0x22" } ] },
                { "Id": "c", "Status": "Failed", "ExpireAt": "" }
            ], "Total": 3 }
        });
        let rows = parse_instances(&v);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].metadata[LABEL_DEVICE_KEY_HASH], "0x11");
        assert_eq!(rows[1].metadata[LABEL_DEVICE_KEY_HASH], "0x22");
        assert!(rows[2].metadata.is_empty());
        assert!(rows[0].is_live() && rows[1].is_live() && !rows[2].is_live());
    }

    #[test]
    fn label_map_builds_string_object() {
        let m = label_map(&delegate_labels("0x11", "0xaa"));
        assert_eq!(m[LABEL_DEVICE_KEY_HASH], "0x11");
        assert_eq!(m[LABEL_ACTOR_OMNI], "0xaa");
        assert_eq!(m[LABEL_MANAGED_BY], MANAGED_BY_VALUE);
    }
}
