//! Broker-driven veFaaS sandbox lifecycle (issue #377) — one dsh-sandbox
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
//! | `PrecacheSandboxImages` | register `CR_IMAGE` in the veFaaS pre-cache (boot + refresh) |
//! | `ListSandboxImages` | find the pre-cache entry for `CR_IMAGE` (#568)   |
//! | `DeleteSandboxImage` | the 移除 half of [`VeFaasClient::refresh_precache`] (#568) |
//! | `GetSandboxImagePrecacheTicket` | best-effort ticket peek during refresh (#568) |
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

/// veFaaS caps each Metadata VALUE at **<64 chars** (`CreateSandbox` →
/// `InvalidParameter: metadata value length must be less than 64`), but a
/// `device_key_hash` / `actor_omni` is a `0x`+64-hex, 66-char string. The label
/// value is therefore the `0x`-stripped, lowercased hash truncated to
/// [`LABEL_VALUE_HEX`] — a deterministic transform applied IDENTICALLY on write
/// ([`delegate_labels`]), the client-side match ([`SandboxInstance::labeled_for`]),
/// and the server-side [`VeFaasClient::list_instances`] filter, so the
/// per-delegate quota key stays consistent. 48 hex = 192 bits: collision-
/// negligible for the handful of delegates one operator runs. The FULL hash
/// still lives in the `DelegateSpawn` audit anchor + the #424 binding manifest;
/// this label is only the internal veFaaS quota key. (#543)
pub const LABEL_VALUE_HEX: usize = 48;

/// Normalize a hash to its veFaaS Metadata label value — see [`LABEL_VALUE_HEX`].
/// Idempotent: an already-normalized value maps to itself, so `labeled_for` can
/// safely apply it to BOTH the stored value and the lookup key.
pub fn label_value(hash: &str) -> String {
    hash.trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .take(LABEL_VALUE_HEX)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Instance statuses that count as "the delegate already has a sandbox" —
/// reuse, never duplicate. `Paused` is veFaaS hibernation (wakes on traffic).
const LIVE_STATUSES: &[&str] = &["ready", "running", "starting", "paused"];

/// How long [`VeFaasClient::refresh_precache`] waits for a deleted pre-cache
/// registration to actually VANISH from `ListSandboxImages` before declaring
/// the delete silently failed (#568 — deletion is not synchronous, and a 200
/// does not prove it happened).
const DELETE_GONE_SECS: u64 = 60;

/// How often [`VeFaasClient::refresh_precache`] polls `ListSandboxImages` while
/// a preheat is running.
const POLL_INTERVAL_SECS: u64 = 10;

/// How often an in-flight preheat logs progress. A real preheat of the ~18 GB
/// sandbox image takes ~30 MINUTES (measured 2026-07-26: submitted 17:29 UTC,
/// `success` at 17:58), so logging every poll produced ~180 identical lines.
const PROGRESS_LOG_SECS: u64 = 120;

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
    /// delegate image in Volcano CR (`CR_IMAGE`, ve-deployment.md §2). Empty =
    /// spawn on the sandbox application's console-configured image.
    pub image: String,
    /// Instance exposed port = the gateway's default proxy target
    /// (`AGENTKEYS_VEFAAS_PORT`, default 8090 — the sandbox bridge).
    pub port: u32,
    /// Instance command (`AGENTKEYS_VEFAAS_COMMAND`, default `/opt/gem/run.sh`
    /// — the base-image entrypoint, same default as spawn-vefaas.sh).
    pub command: String,
    /// Instance lifetime in minutes (`AGENTKEYS_VEFAAS_TIMEOUT_MINUTES`,
    /// default 1440; veFaaS bounds are 3–1440). Also the amount each resolve
    /// re-extends by, so an ACTIVE device's sandbox never expires while an
    /// abandoned one dies within this window.
    pub timeout_minutes: u32,
    /// How long an instance this broker created or adopted stays REMEMBERED
    /// per delegate (`AGENTKEYS_VEFAAS_RECENT_INSTANCE_SECS`, default 600,
    /// 0..=3600; 0 = off). Within that window an ensure whose ListSandboxes
    /// view shows no live instance for the delegate DESCRIBES the remembered
    /// one first — the list lags the platform's own state right after a
    /// create/adopt (measured 2026-09-19 06:30:52 CST: 60 ms after the
    /// sweeper adopted chef's instance, a resolve's ensure listed nothing
    /// live and created a duplicate that answered every ask twice).
    pub recent_instance_secs: u32,
    /// Per-request HTTP timeout for `CreateSandbox` in seconds
    /// (`AGENTKEYS_VEFAAS_CREATE_TIMEOUT_SECS`, default 180; bounds 15..=600).
    /// SEPARATE from `timeout_minutes` (the sandbox LIFETIME): provisioning an
    /// instance from a large preheated image routinely exceeds the 15s default
    /// client timeout (#543 "operation timed out" on a 17 GB image spawn),
    /// so this ONE call gets a generous ceiling while the quick lifecycle calls
    /// keep the short default.
    pub create_timeout_secs: u32,
    /// #589 — after a `CreateSandbox` 408 `function_cold_start_timeout`, keep
    /// polling the named instance for up to this many seconds and ADOPT it
    /// once Ready (`AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS`, default 120,
    /// bounds 0..=600; 0 disables the resume). veFaaS caps the synchronous
    /// create at ~29s but the pod keeps booting server-side, and a blind retry
    /// CREATES A DUPLICATE — a booting instance is invisible to the reuse
    /// pre-check (measured 2026-08-01: 3 creates → 3 Ready instances → 3 chat
    /// loops on one channel).
    pub coldstart_wait_secs: u32,
    /// Refuse to create past this many instances under the application
    /// (`AGENTKEYS_VEFAAS_MAX_INSTANCES`, default 20) — bounds the blast
    /// radius if label matching ever breaks (see module docs).
    pub max_instances: usize,
    /// #543 fail-closed: `AGENTKEYS_ALLOW_DIRECT_ARK=1` opts this stack into
    /// injecting the SHARED host ark key into non-gate-provisioned sandboxes
    /// (UNMETERED). Default false — such creates are refused.
    pub allow_direct_ark: bool,
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
        let create_timeout_secs = parse_u32("AGENTKEYS_VEFAAS_CREATE_TIMEOUT_SECS", 180)?;
        if !(15..=600).contains(&create_timeout_secs) {
            bail!(
                "AGENTKEYS_VEFAAS_CREATE_TIMEOUT_SECS must be 15..=600, got {create_timeout_secs}"
            );
        }
        let coldstart_wait_secs = parse_u32("AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS", 120)?;
        if coldstart_wait_secs > 600 {
            bail!(
                "AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS must be 0..=600, got {coldstart_wait_secs}"
            );
        }
        let recent_instance_secs = parse_u32("AGENTKEYS_VEFAAS_RECENT_INSTANCE_SECS", 600)?;
        if recent_instance_secs > 3600 {
            bail!(
                "AGENTKEYS_VEFAAS_RECENT_INSTANCE_SECS must be 0..=3600, got {recent_instance_secs}"
            );
        }
        Ok(Some(Self {
            function_id,
            gateway_url,
            image: non_empty("CR_IMAGE").unwrap_or_default(),
            port: parse_u32("AGENTKEYS_VEFAAS_PORT", 8090)?,
            command: non_empty("AGENTKEYS_VEFAAS_COMMAND")
                .unwrap_or_else(|| "/opt/gem/run.sh".to_string()),
            timeout_minutes,
            create_timeout_secs,
            coldstart_wait_secs,
            recent_instance_secs,
            max_instances: parse_u32("AGENTKEYS_VEFAAS_MAX_INSTANCES", 20)? as usize,
            allow_direct_ark: non_empty("AGENTKEYS_ALLOW_DIRECT_ARK")
                .is_some_and(|v| v.trim() == "1"),
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
        // Normalize BOTH sides (#543): the stored value is the truncated label,
        // the lookup key is the full hash — `label_value` is idempotent, so this
        // matches whether the stored value was written truncated (production) or
        // raw (unit fixtures).
        self.metadata
            .get(LABEL_DEVICE_KEY_HASH)
            .is_some_and(|v| label_value(v) == label_value(device_key_hash))
            && self
                .metadata
                .get(LABEL_MANAGED_BY)
                .is_some_and(|v| v == MANAGED_BY_VALUE)
    }
}

/// One pre-cache registration row from `ListSandboxImages` (#568) — the
/// console 沙箱镜像 table. Field names are the live wire spelling (probed
/// 2026-07-24); see [`VeFaasClient::list_sandbox_images`] for the contract.
#[derive(Debug, Clone)]
pub struct SandboxImage {
    /// veFaaS-minted registration id (console 镜像ID, e.g. `gqgjhemfmf`) —
    /// the `DeleteSandboxImage` handle. NOT a CR artifact id.
    pub image_id: String,
    /// The registered TAG ref (veFaaS cannot register digests).
    pub image_url: String,
    /// `"success"` = console 已预热; failures carry a reason.
    pub precache_status: String,
    pub precache_status_reason: String,
    pub update_time: String,
}

/// One instance's spawn-frozen image identity (#577): `DescribeSandbox.
/// ImageInfo` — the pre-cache REGISTRATION id the instance froze (`Id`, the
/// same handle `DeleteSandboxImage` pins on, probed live 2026-07-24) plus the
/// CR tag it was spawned from (`SourceImageUrl`). Because a precache refresh
/// (#568) mints a NEW registration id for the same tag, `frozen id ≠ current
/// registration id` is exactly "this instance runs older bits than the
/// pre-cache serves" — the staleness signal the API's digest-less List cannot
/// give any other way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceImageInfo {
    /// The pre-cache registration id frozen at spawn (`ImageInfo.Id`).
    pub registration_id: String,
    /// The CR tag ref the instance was spawned from (`ImageInfo.SourceImageUrl`).
    pub source_image_url: String,
}

/// Pure #577 staleness verdict: does a live instance run OLDER bits than the
/// current pre-cache registration for the broker's `CR_IMAGE`?
///
/// `None` = unknowable (the instance runs the app's console-default image, or
/// there is no current registration to compare against) — surfaced as
/// "unknown", never guessed. `Some(true)` when the frozen registration id
/// differs from the current one (a refresh re-registered the tag since this
/// instance spawned) OR the tag ref itself changed (`CR_IMAGE` moved).
pub fn image_stale(
    booted: Option<&InstanceImageInfo>,
    current: Option<&SandboxImage>,
) -> Option<bool> {
    let (booted, current) = (booted?, current?);
    if booted.source_image_url.trim() != current.image_url.trim() {
        return Some(true);
    }
    Some(booted.registration_id.trim() != current.image_id.trim())
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
    /// Optional Ark EMBEDDING endpoint forwarded to instances
    /// (`OPENVIKING_EMBED_MODEL` + `OPENVIKING_EMBED_DIMENSION`) — the baked
    /// OpenViking engine renders them into ov.conf (start-openviking.sh) so a
    /// spawned sandbox ranks memory SEMANTICALLY (#399). Absent = the engine
    /// boots without an embedder and the hook stays on the lexical fallback
    /// (loud warn in the sandbox log — never a failure).
    openviking_embed_model: Option<String>,
    openviking_embed_dimension: Option<String>,
    /// Spawns are serialized so two concurrent resolves for the same (or
    /// different) delegates can't race list→create into duplicates. Spawn is
    /// a rare event (pair / device boot); one lock is simpler than a
    /// per-device map and the contention is irrelevant at this rate.
    ensure_lock: tokio::sync::Mutex<()>,
    /// Instances this broker created or adopted, per delegate label — the
    /// list view's lag bridge (see [`VeFaasConfig::recent_instance_secs`]).
    recent_instances: std::sync::Mutex<HashMap<String, (String, std::time::Instant)>>,
}

/// The remembered instance for `key`, if still within `ttl` of when it was
/// remembered — pure, so the lag bridge's arithmetic is testable.
fn remembered_instance(
    memo: &HashMap<String, (String, std::time::Instant)>,
    key: &str,
    now: std::time::Instant,
    ttl: std::time::Duration,
) -> Option<String> {
    let (id, at) = memo.get(key)?;
    (now.duration_since(*at) < ttl).then(|| id.clone())
}

impl VeFaasClient {
    /// Construct from the environment — read ONCE here, never re-read later.
    /// Returns `Ok(None)` when the sandbox lifecycle is not configured (the
    /// AWS broker host, or a VE host predating #377).
    ///
    ///   SANDBOX_FUNCTION_ID                the sandbox application (enables the feature)
    ///   SANDBOX_GATEWAY_URL                devices' agent base URL (required with the above)
    ///   CR_IMAGE                           delegate image in Volcano CR (empty = app default)
    ///   AGENTKEYS_VEFAAS_PORT              default 8090
    ///   AGENTKEYS_VEFAAS_COMMAND           default /opt/gem/run.sh
    ///   AGENTKEYS_VEFAAS_TIMEOUT_MINUTES   default 1440 (3..=1440)
    ///   AGENTKEYS_VEFAAS_MAX_INSTANCES     default 20
    ///   AGENTKEYS_VEFAAS_HOST              default open.volcengineapi.com
    ///   VOLCENGINE_ACCESS_KEY / _SECRET_KEY  broker VE identity (required with the above)
    ///   VOLCENGINE_REGION                  default cn-beijing
    ///   SEARCH_MODEL                       optional, forwarded to instances
    ///   OPENVIKING_EMBED_MODEL             optional Ark embedding endpoint id, forwarded (#399)
    ///   OPENVIKING_EMBED_DIMENSION         optional, forwarded with the model (must match it)
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
            openviking_embed_model: std::env::var("OPENVIKING_EMBED_MODEL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            openviking_embed_dimension: std::env::var("OPENVIKING_EMBED_DIMENSION")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            ensure_lock: tokio::sync::Mutex::new(()),
            recent_instances: std::sync::Mutex::new(HashMap::new()),
        }))
    }

    fn remember_instance(&self, device_key_hash: &str, sandbox_id: &str) {
        if self.config.recent_instance_secs == 0 {
            return;
        }
        if let Ok(mut memo) = self.recent_instances.lock() {
            memo.retain(|_, (_, at)| {
                at.elapsed().as_secs() < u64::from(self.config.recent_instance_secs)
            });
            memo.insert(
                label_value(device_key_hash),
                (sandbox_id.to_string(), std::time::Instant::now()),
            );
        }
    }

    fn forget_instance(&self, device_key_hash: &str) {
        if let Ok(mut memo) = self.recent_instances.lock() {
            memo.remove(&label_value(device_key_hash));
        }
    }

    /// The lag bridge: when the list shows nothing live for the delegate but
    /// this broker remembers creating/adopting an instance recently, ask the
    /// platform about THAT instance — `Some` when it is live (reuse it).
    async fn remembered_live_instance(&self, device_key_hash: &str) -> Option<SandboxInstance> {
        let ttl = std::time::Duration::from_secs(u64::from(self.config.recent_instance_secs));
        let id = {
            let memo = self.recent_instances.lock().ok()?;
            remembered_instance(
                &memo,
                &label_value(device_key_hash),
                std::time::Instant::now(),
                ttl,
            )?
        };
        match self.describe(&id).await {
            Ok((status, expire_at)) => {
                let inst = SandboxInstance {
                    id: id.clone(),
                    status,
                    expire_at,
                    metadata: HashMap::new(),
                };
                if inst.is_live() {
                    tracing::info!(
                        sandbox_id = %id,
                        status = %inst.status,
                        "#377 ensure: the list showed no live instance for this delegate, but the \
                         one this broker created moments ago is live — reusing it (list lag)"
                    );
                    Some(inst)
                } else {
                    self.forget_instance(device_key_hash);
                    None
                }
            }
            Err(e) => {
                tracing::info!(sandbox_id = %id, error = %format!("{e:#}"), "#377 ensure: remembered instance no longer describable — forgotten");
                self.forget_instance(device_key_hash);
                None
            }
        }
    }

    /// The base URL devices talk to (`agent_url` in the resolve response).
    pub fn agent_url(&self) -> &str {
        &self.config.gateway_url
    }

    /// `PrecacheSandboxImages` — warm the veFaaS image cache for our `CR_IMAGE`
    /// so `CreateSandbox` doesn't 404 `ResourceNotFound` ("Sandbox image not found
    /// in pre cache sandbox image list") on a freshly-pushed image. Precaches the
    /// configured image; a no-op (empty `Ok`) when `CR_IMAGE` is unset (spawns then
    /// use the app's console-configured image). veFaaS precache is ASYNC — this
    /// returns the ticket id; poll `GetSandboxImagePrecacheTicket` / watch the
    /// console 镜像预热 for "Preheated". `Region` is a required parameter (#543).
    ///
    /// The image list field is **`ImageUrls`**, not `Images` — corrected against
    /// the live API 2026-07-23. The wrong name had been in place since #543 but
    /// was INVISIBLE: the call 403'd on a missing `vefaas:PrecacheSandboxImages`
    /// grant, so it never reached parameter validation. The moment the IAM grant
    /// landed the API answered `400 MissingParameter.ImageUrls`. Two stacked
    /// faults, the outer one masking the inner — hence no silent fallbacks here:
    /// every precache failure is surfaced with the VE `{Code, Message}` pair.
    pub async fn precache_image(&self) -> Result<String> {
        if self.config.image.trim().is_empty() {
            return Ok(String::new());
        }
        let body = serde_json::json!({
            "ImageUrls": [self.config.image],
            "Region": self.config.region,
        });
        // "already exists" is the IDEMPOTENT case, not a failure: veFaaS 400s when
        // the image URL is already registered in the precache list, which is the
        // normal state on every boot after the first. Treating it as an error made
        // a healthy broker log a scary WARN at every start (and buried the two REAL
        // faults underneath it — the missing IAM grant and the wrong field name).
        // NOTE for the operator: "already exists" says the URL is registered, NOT
        // that it holds the latest bits. A re-push to the SAME tag does not
        // re-register; refresh it after every push — [`Self::refresh_precache`]
        // (the `agentkeys-broker-server precache-refresh` verb, run by
        // setup-image.sh post-push) — or the sandbox keeps booting the
        // previously cached content. The List response exposes NO digest
        // (probed 2026-07-24), so staleness is NOT detectable from the API:
        // the boot precache cannot self-heal a moved tag, only register an
        // absent one. Refresh is therefore an explicit post-push step.
        let v = match self.vefaas_call("PrecacheSandboxImages", body).await {
            Ok(v) => v,
            Err(e) if e.to_string().contains("already exists") => {
                tracing::info!(
                    image = %self.config.image,
                    "veFaaS precache: image URL already registered (idempotent no-op). If the \
                     tag was re-pushed since it was registered, run `agentkeys-broker-server \
                     precache-refresh` (#568) — a same-tag re-push does NOT re-cache."
                );
                return Ok(String::new());
            }
            Err(e) => return Err(e),
        };
        Ok(v["Result"]["TicketId"]
            .as_str()
            .or_else(|| v["TicketId"].as_str())
            .unwrap_or("")
            .to_string())
    }

    /// `ListSandboxImages` — the account's PRE-CACHE registrations (what the
    /// console 沙箱镜像 page shows), NOT the CR catalog. Shapes confirmed live
    /// 2026-07-24 (broker identity, after the #568 IAM grant):
    ///
    /// Request: `ImageType` is REQUIRED and LOWERCASE — `"private"` (our CR
    /// images) or `"public"` (the vefaas-public catalog); an empty value 400s
    /// `InvalidParameter: sandbox image type is empty`, a capitalized one 400s
    /// `… type is invalid`. Optional `PageSize`/`PageNumber`/`Filters[{Key,Values[]}]`.
    /// One page of 100 always suffices: the account pre-cache cap is 20 images.
    ///
    /// Response: `Result.Images[] { ImageGroup, ImageId, ImageUrl,
    /// PrecacheStatus, PrecacheStatusReason, UpdateTime, Description? }` +
    /// `Result.TotalCount`. `PrecacheStatus == "success"` is the console's
    /// 已预热. There is NO digest/content field — which is why a same-tag
    /// re-push is undetectable and [`Self::refresh_precache`] must delete +
    /// re-add unconditionally.
    pub async fn list_sandbox_images(&self) -> Result<Vec<SandboxImage>> {
        let v = self
            .vefaas_call(
                "ListSandboxImages",
                serde_json::json!({ "ImageType": "private", "PageSize": 100 }),
            )
            .await?;
        Ok(parse_sandbox_images(&v))
    }

    /// `DeleteSandboxImage { ImageId, Region }` — remove one pre-cache
    /// registration (the console 移除). Only the REGISTRATION: the CR content
    /// is untouched and running sandboxes keep the image they froze at spawn.
    ///
    /// The failure mode never touches HTTP status (probed live 2026-07-24):
    /// the call answers HTTP 200 with `Result.Status` = `"success"` OR
    /// `"failed"`. **In-use pin**: while any LIVE sandbox instance runs this
    /// image, `Result: { Status: "failed", RelatedSandboxApplications:
    /// [<app>] }` — and nothing is deleted. (`DescribeSandbox.ImageInfo.Id`
    /// carries the registration id an instance was spawned from — that
    /// reference is the pin; the app's own configured image is NOT involved,
    /// verified against an app configured with the stock AIO image.) Parsed
    /// here into a real error naming the archive remediation. `Region` rides
    /// the body like `PrecacheSandboxImages` requires (harmless if optional
    /// here), and [`Self::refresh_precache`] additionally verifies the entry
    /// actually disappears — a bare 200 proves nothing.
    pub async fn delete_sandbox_image(&self, image_id: &str) -> Result<()> {
        let v = self
            .vefaas_call(
                "DeleteSandboxImage",
                serde_json::json!({ "ImageId": image_id, "Region": self.config.region }),
            )
            .await?;
        tracing::info!(image_id = %image_id, response = %v, "DeleteSandboxImage");
        if v["Result"]["Status"].as_str().unwrap_or_default() == "failed" {
            let apps: Vec<String> = v["Result"]["RelatedSandboxApplications"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            bail!(
                "DeleteSandboxImage {image_id} refused: Result.Status=failed — the registration \
                 is IN USE by live sandbox instance(s) under application(s) {apps:?}. veFaaS \
                 only frees a registration once no live instance runs it: ARCHIVE the \
                 delegate(s) (parent-control, Touch ID) so their sandboxes are killed, then \
                 re-run the refresh."
            );
        }
        Ok(())
    }

    /// The live instances currently RUNNING `image` (their spawn-time
    /// `ImageInfo.SourceImageUrl` matches) — the exact set that pins the
    /// pre-cache registration against deletion. Used by
    /// [`Self::refresh_precache`] to fail BEFORE the delete with a precise
    /// who-to-archive list instead of after it with a bare app id.
    pub async fn instances_running_image(&self, image: &str) -> Result<Vec<SandboxInstance>> {
        let mut pinned = Vec::new();
        for inst in self.list_instances::<&str>(None).await? {
            if !inst.is_live() {
                continue;
            }
            match self.describe_image_source(&inst.id).await {
                Ok(Some(src)) if src.trim() == image.trim() => pinned.push(inst),
                Ok(_) => {}
                // A describe hiccup must not hide a pinner — the delete's own
                // Status=failed parse + the GONE gate still backstop this.
                Err(e) => {
                    tracing::warn!(sandbox_id = %inst.id, error = %e, "DescribeSandbox failed while scanning for image pinners")
                }
            }
        }
        Ok(pinned)
    }

    /// `DescribeSandbox` → `Result.ImageInfo.SourceImageUrl` — the CR ref the
    /// instance was spawned from (`ImageInfo.Image` is veFaaS's INTERNAL
    /// synced copy, re-tagged by registration id: `…/vefaas-sync-image/
    /// <acct>:<registration-id>` — the "precached copy" made concrete).
    /// `None` when the instance runs the app's default image (no ImageInfo).
    async fn describe_image_source(&self, sandbox_id: &str) -> Result<Option<String>> {
        Ok(self
            .describe_image_info(sandbox_id)
            .await?
            .map(|i| i.source_image_url))
    }

    /// `DescribeSandbox` → the instance's frozen `ImageInfo` (#577): the
    /// pre-cache registration id (`Id` — the pin `DeleteSandboxImage` reports)
    /// together with the source tag ref. `None` when the instance runs the
    /// app's console-default image (no ImageInfo on the response).
    pub async fn describe_image_info(&self, sandbox_id: &str) -> Result<Option<InstanceImageInfo>> {
        let v = self
            .vefaas_call(
                "DescribeSandbox",
                serde_json::json!({
                    "FunctionId": self.config.function_id,
                    "SandboxId": sandbox_id,
                }),
            )
            .await?;
        let info = &v["Result"]["ImageInfo"];
        let source = info["SourceImageUrl"].as_str().unwrap_or_default();
        if source.is_empty() {
            return Ok(None);
        }
        Ok(Some(InstanceImageInfo {
            registration_id: info["Id"].as_str().unwrap_or_default().to_string(),
            source_image_url: source.to_string(),
        }))
    }

    /// The current pre-cache registration row for this broker's `CR_IMAGE`
    /// (#577 staleness anchor): what a CREATE issued right now would freeze.
    /// `Ok(None)` when `CR_IMAGE` is unset (spawns use the app default) or the
    /// tag has no registration yet.
    pub async fn current_image_registration(&self) -> Result<Option<SandboxImage>> {
        let image = self.config.image.trim();
        if image.is_empty() {
            return Ok(None);
        }
        let rows = self.list_sandbox_images().await?;
        Ok(find_sandbox_image(&rows, image).cloned())
    }

    /// The delegate's LIVE labeled instances (#577) — the same match
    /// `kill_for_device` kills, without the kill: what an update snapshots
    /// before tearing down. Normally 0 or 1 (the ensure quota invariant).
    pub async fn live_instances_for_device(
        &self,
        device_key_hash: &str,
    ) -> Result<Vec<SandboxInstance>> {
        let all = self
            .list_instances(Some(&[(
                LABEL_DEVICE_KEY_HASH,
                label_value(device_key_hash),
            )]))
            .await?;
        Ok(all
            .into_iter()
            .filter(|i| i.labeled_for(device_key_hash) && i.is_live())
            .collect())
    }

    /// `GetSandboxImagePrecacheTicket { TicketId }` — the async-precache
    /// ticket minted by `PrecacheSandboxImages`. Returns the raw JSON: the
    /// refresh flow treats it as best-effort diagnostics only and polls
    /// [`Self::list_sandbox_images`]' `PrecacheStatus` as the ground truth
    /// (the ticket's field grammar is thinner than the entry row's).
    pub async fn get_precache_ticket(&self, ticket_id: &str) -> Result<serde_json::Value> {
        self.vefaas_call(
            "GetSandboxImagePrecacheTicket",
            serde_json::json!({ "TicketId": ticket_id }),
        )
        .await
    }

    /// #568 — the post-push precache REFRESH: List → Delete the entry for
    /// `CR_IMAGE` → **verify it is GONE** → Precache → poll until the fresh
    /// registration reports `PrecacheStatus success` (已预热) or `poll_timeout`
    /// elapses.
    ///
    /// Exists because veFaaS spawns the PRE-CACHED copy of a tag, not what the
    /// registry serves: a same-tag re-push is invisible, `PrecacheSandboxImages`
    /// answers `already exists` without re-pulling, and the API exposes no
    /// digest to compare — so the ONLY way to make a pushed tag live is
    /// delete + re-add (preheat is tag-only and always pulls current content;
    /// proven in the 2026-07-23 silent-chat incident, automated here).
    ///
    /// The GONE gate is load-bearing, not paranoia (first live run,
    /// 2026-07-24): `DeleteSandboxImage` can answer 200 while the entry
    /// SURVIVES (a body-`Region` miss deletes nothing, and deletion may lag).
    /// Without the gate that run "succeeded" end-to-end — delete 200, re-add
    /// `already exists`, poll saw the OLD entry's `success` with its
    /// UNCHANGED UpdateTime — a false green over exactly the staleness this
    /// verb exists to kill. Hence: the delete must be OBSERVED (entry absent
    /// from List) before the re-add, and `already exists` after observed
    /// absence is a hard error, never a shrug. Loud on every failure; a
    /// mid-poll transient List error is retried until the deadline, never
    /// treated as success.
    pub async fn refresh_precache(
        &self,
        poll_timeout: std::time::Duration,
        kill_pinners: bool,
    ) -> Result<String> {
        let image = self.config.image.trim();
        if image.is_empty() {
            bail!(
                "CR_IMAGE is unset — nothing to refresh (spawns use the sandbox application's \
                 console-configured image; set CR_IMAGE in the env family first)"
            );
        }

        let rows = self.list_sandbox_images().await.context(
            "ListSandboxImages failed — cannot see the current pre-cache registrations \
             (is vefaas:ListSandboxImages granted to this identity? #568 policy)",
        )?;
        if let Some(row) = find_sandbox_image(&rows, image) {
            // RESUME, never RESTART (#568 follow-up, 2026-07-26). An entry that
            // is still non-terminal (`caching`) was registered by an EARLIER
            // refresh — i.e. after the push — so it is already pulling the
            // CURRENT tag content. Deleting it would throw that progress away
            // and restart a ~30-minute preheat, which is precisely what the old
            // timeout message told the operator to do. Resuming is what makes a
            // timed-out run safely re-runnable.
            //
            // Edge case, stated so it is not a surprise: if you pushed NEW bits
            // WHILE a preheat was already in flight, this waits on the older
            // in-flight pull — let it finish, then run precache-refresh again to
            // cycle onto the new content (that second run sees `success` and
            // takes the delete + re-add path below).
            if precache_terminal(&row.precache_status).is_none() {
                tracing::info!(
                    image_id = %row.image_id, status = %row.precache_status,
                    updated = %row.update_time,
                    "precache already IN FLIGHT for this URL — resuming the wait (no delete/re-add, \
                     so an earlier run's progress is kept)"
                );
                return self.poll_until_preheated(image, poll_timeout).await;
            }
            // Pinner pre-flight: veFaaS refuses to free a registration while
            // any LIVE instance runs it (Delete answers 200/Status=failed).
            // Name the exact instances so the operator knows WHO to archive —
            // archiving delegates is the ceremony's designed human step
            // (Touch ID, parent-control), it just has to happen BEFORE the
            // refresh, not after. TOCTOU between this check and the delete is
            // covered by the delete's own Status=failed parse + the GONE gate.
            let pinners = self.instances_running_image(image).await?;
            if !pinners.is_empty() {
                let who: Vec<String> = pinners
                    .iter()
                    .map(|i| {
                        format!(
                            "{} (delegate {}, expires {})",
                            i.id,
                            i.metadata
                                .get(LABEL_DEVICE_KEY_HASH)
                                .map(String::as_str)
                                .unwrap_or("?"),
                            i.expire_at
                        )
                    })
                    .collect();
                if !kill_pinners {
                    bail!(
                        "precache refresh BLOCKED — {} live sandbox instance(s) still run {image}, \
                         and veFaaS refuses to free a pinned registration: {}. Two remedies (#577): \
                         (a) re-run with --kill-pinners — kill-ONLY, the on-chain bindings stay \
                         active, and once the preheat completes each delegate comes back on the \
                         NEW image via one parent-control 'update runtime' click (no archive \
                         ceremony); or (b) archive the delegate(s) in parent-control (Touch ID) \
                         if you actually want them GONE. Then re-run the refresh: \
                         bash scripts/operator/setup-image.sh --refresh-only (or --push-only ONLY \
                         on the host that built+pushed the image — elsewhere it would overwrite \
                         the fresh tag with a stale local copy, #578). NOTE: the #598 versioned \
                         cycle (default) avoids this entirely — a NEW tag preheats alongside the \
                         pinned registration, no delete needed; this stop means you are refreshing \
                         a MUTABLE tag a live instance runs.",
                        pinners.len(),
                        who.join("; ")
                    );
                }
                // #577 --kill-pinners: kill-only unpin (bindings stay active;
                // delegates return on the fresh image via the update click).
                for p in &pinners {
                    tracing::info!(sandbox_id = %p.id, "killing pinning instance (--kill-pinners)");
                    self.kill(&p.id)
                        .await
                        .with_context(|| format!("KillSandbox {} (--kill-pinners)", p.id))?;
                }
                // The pin releases asynchronously with the instance teardown —
                // wait until the scan shows no live runner before the delete
                // (its own Status=failed parse + the GONE gate still backstop).
                let unpin_deadline =
                    std::time::Instant::now() + std::time::Duration::from_secs(DELETE_GONE_SECS);
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    match self.instances_running_image(image).await {
                        Ok(still) if still.is_empty() => break,
                        Ok(still) => tracing::info!(
                            remaining = still.len(),
                            "waiting for killed instance(s) to release the registration pin…"
                        ),
                        Err(e) => {
                            tracing::warn!(error = %e, "pin re-scan failed — retrying")
                        }
                    }
                    if std::time::Instant::now() >= unpin_deadline {
                        bail!(
                            "killed {} pinning instance(s) but live runners of {image} are still \
                             listed after {DELETE_GONE_SECS}s — not proceeding to the delete \
                             (it would 200/Status=failed). Re-run precache-refresh.",
                            pinners.len()
                        );
                    }
                }
            }
            tracing::info!(
                image_id = %row.image_id, status = %row.precache_status,
                updated = %row.update_time,
                "precache refresh: deleting the existing registration (移除)"
            );
            self.delete_sandbox_image(&row.image_id)
                .await
                .with_context(|| format!("DeleteSandboxImage {} ({image})", row.image_id))?;

            // GONE gate — a 200 from Delete proves nothing (see the method
            // docs). Poll until the entry vanishes from List; if it survives
            // the window, the delete silently failed and re-adding would
            // `already exists` over the stale content.
            let gone_deadline =
                std::time::Instant::now() + std::time::Duration::from_secs(DELETE_GONE_SECS);
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                match self.list_sandbox_images().await {
                    Ok(rows) => {
                        if find_sandbox_image(&rows, image).is_none() {
                            tracing::info!("registration removed (observed absent) — re-adding");
                            break;
                        }
                        tracing::info!("registration still listed after delete — waiting…");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ListSandboxImages poll failed — retrying")
                    }
                }
                if std::time::Instant::now() >= gone_deadline {
                    bail!(
                        "DeleteSandboxImage answered 200 but the registration for {image} is \
                         STILL LISTED after {DELETE_GONE_SECS}s — the delete silently failed \
                         (this is the false-green trap the first live run hit; the pre-cache \
                         still serves the PREVIOUS content). Nothing was harmed, but the \
                         refresh did NOT happen — investigate DeleteSandboxImage's params \
                         (body Region?) before trusting this stack's image cycle."
                    );
                }
            }
        } else {
            tracing::info!(
                image = %image,
                "precache refresh: no existing registration for this URL — fresh registration"
            );
        }

        let ticket = self
            .precache_image()
            .await
            .context("PrecacheSandboxImages (the re-add half) failed — the entry was deleted; re-run this refresh (or restart the broker: boot re-registers) so spawns don't 404 ResourceNotFound")?;
        if ticket.is_empty() {
            // precache_image maps `already exists` to Ok("") — but the GONE
            // gate above OBSERVED the registration absent, so an
            // `already exists` here means veFaaS resurrected/never-freed the
            // old entry and the re-pull did NOT happen. False green — refuse.
            bail!(
                "PrecacheSandboxImages answered `already exists` AFTER the registration was \
                 observed absent — veFaaS did not accept a fresh registration for {image}, so \
                 the cached content was NOT refreshed. Re-run precache-refresh; if it \
                 persists, check the entry in the console (沙箱镜像) and the CR instance."
            );
        }
        tracing::info!(ticket = %ticket, "precache re-add submitted — polling until Preheated (已预热)");
        // Best-effort shape capture + early diagnostics; never load-bearing.
        match self.get_precache_ticket(&ticket).await {
            Ok(v) => {
                tracing::info!(ticket = %ticket, response = %v, "GetSandboxImagePrecacheTicket")
            }
            Err(e) => {
                tracing::warn!(ticket = %ticket, error = %e, "GetSandboxImagePrecacheTicket failed (non-fatal — the List poll is the ground truth)")
            }
        }

        self.poll_until_preheated(image, poll_timeout).await
    }

    /// Poll `ListSandboxImages` until the registration for `image` reaches a
    /// terminal `PrecacheStatus` — shared by the fresh delete+re-add path and
    /// the resume path, so both report identically.
    ///
    /// `ListSandboxImages` is the ground truth (the ticket's grammar is
    /// thinner), and a transient List error is retried rather than treated as
    /// failure — only the deadline exits loud.
    async fn poll_until_preheated(
        &self,
        image: &str,
        poll_timeout: std::time::Duration,
    ) -> Result<String> {
        let started = std::time::Instant::now();
        let deadline = started + poll_timeout;
        let mut last_status = String::from("(entry not observed yet)");
        let mut last_log: Option<std::time::Instant> = None;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
            match self.list_sandbox_images().await {
                Ok(rows) => {
                    if let Some(row) = find_sandbox_image(&rows, image) {
                        last_status = row.precache_status.clone();
                        match precache_terminal(&row.precache_status) {
                            Some(true) => {
                                tracing::info!(
                                    image_id = %row.image_id, updated = %row.update_time,
                                    elapsed_s = started.elapsed().as_secs(),
                                    "precache COMPLETE — registration preheated (已预热)"
                                );
                                return Ok(row.image_id.clone());
                            }
                            Some(false) => bail!(
                                "precache FAILED — veFaaS reports PrecacheStatus={} \
                                 reason={:?} for {image}. Fix the cause (CR instance running? \
                                 image pullable?) and re-run precache-refresh.",
                                row.precache_status,
                                row.precache_status_reason
                            ),
                            None => {
                                if last_log.is_none_or(|t| {
                                    t.elapsed() >= std::time::Duration::from_secs(PROGRESS_LOG_SECS)
                                }) {
                                    tracing::info!(
                                        status = %row.precache_status,
                                        elapsed_s = started.elapsed().as_secs(),
                                        timeout_s = poll_timeout.as_secs(),
                                        "precache in flight… (a full image preheat runs ~30 min)"
                                    );
                                    last_log = Some(std::time::Instant::now());
                                }
                            }
                        }
                    } else {
                        last_status = "(entry not listed yet)".to_string();
                        tracing::info!("precache entry not listed yet…");
                    }
                }
                // Transient List failures must not abort a long preheat wait —
                // keep polling until the deadline; the deadline is the loud exit.
                Err(e) => tracing::warn!(error = %e, "ListSandboxImages poll failed — retrying"),
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "precache refresh TIMED OUT after {}s — last observed PrecacheStatus: \
                     {last_status}. A full preheat of this image is SLOW: ~30 min measured \
                     (2026-07-26). NOTHING IS BROKEN AND NOTHING WAS LOST — the push succeeded \
                     and the entry keeps preheating server-side. Just re-run precache-refresh: \
                     it RESUMES the wait on an in-flight entry (it will NOT delete/restart a \
                     preheat that is still caching). Raise --timeout-secs to wait longer in one \
                     go; watch it meanwhile in the console (沙箱镜像) or with \
                     `ve vefaas ListSandboxImages --ImageType private`.",
                    poll_timeout.as_secs()
                );
            }
        }
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
        let mut req = self
            .http
            .post(&url)
            .header("Content-Type", &signed.content_type)
            .header("X-Date", &signed.x_date)
            .header("X-Content-Sha256", &signed.x_content_sha256)
            .header("Authorization", &signed.authorization)
            .body(body_str);
        // CreateSandbox provisions an instance from the (large, preheated) image and
        // routinely takes longer than the default 15s client timeout — the #543
        // "operation timed out" on a 17 GB spawn. Give this ONE call a generous,
        // env-tunable per-request ceiling; the quick lifecycle calls keep the default.
        if action == "CreateSandbox" {
            req = req.timeout(std::time::Duration::from_secs(
                self.config.create_timeout_secs as u64,
            ));
        }
        let resp = req
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
    pub async fn list_instances<V: AsRef<str>>(
        &self,
        label_filter: Option<&[(&str, V)]>,
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

    /// `DescribeSandbox` → `(status, expire_at)` for one instance. `expire_at`
    /// is RFC3339-normalized like the list path ([`normalize_expire_at`]) —
    /// both entry points for the vendor field, one shape out.
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
            normalize_expire_at(v["Result"]["ExpireAt"].as_str().unwrap_or("?")),
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
    ///
    /// #589 measured: veFaaS caps an instance's expiry at
    /// `create_time + <create-time Timeout>`, so with the full 1440-min lease
    /// at create every extension is rejected (`new expire time … is forbiden`)
    /// BY CONSTRUCTION — that rejection is the steady state, not a fault, and
    /// the post-expiry path is the #546 spawn-context re-create. A shorter
    /// initial lease (making extends real, idle instances cheaper) is the
    /// open follow-up decision on #589.
    pub async fn extend(&self, sandbox_id: &str) -> Result<()> {
        match self
            .vefaas_call(
                "SetSandboxTimeout",
                serde_json::json!({
                    "FunctionId": self.config.function_id,
                    "SandboxId": sandbox_id,
                    "Timeout": self.config.timeout_minutes,
                }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e)
                if e.to_string().contains("expire time") && e.to_string().contains("forbiden") =>
            {
                tracing::debug!(
                    sandbox_id = %sandbox_id,
                    "SetSandboxTimeout at the lifetime cap (expected with a full-lease create) — \
                     instance keeps its current expiry (#589)"
                );
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// The instance env for a delegate's sandbox: the #338 ark family
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
        // #399 — semantic memory ranking: the baked OpenViking engine needs the
        // Ark embedding endpoint; dimension only travels with a model.
        if let Some(m) = &self.openviking_embed_model {
            envs.push(("OPENVIKING_EMBED_MODEL".to_string(), m.clone()));
            if let Some(d) = &self.openviking_embed_dimension {
                envs.push(("OPENVIKING_EMBED_DIMENSION".to_string(), d.clone()));
            }
        }
        Ok(envs)
    }

    /// `CreateSandbox` labeled for the delegate → the new `SandboxId`.
    /// `extra_envs` (#427 spawn ceremony) are merged OVER the resolver set —
    /// a colliding key (e.g. `ARK_BASE_URL`/`ARK_API_KEY` pointed at the
    /// per-delegate gate relay key) replaces the direct-ark value.
    async fn create_for_delegate(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        extra_envs: &[(String, String)],
    ) -> Result<String> {
        crate::sandbox_backend::direct_ark_guard(extra_envs, self.config.allow_direct_ark)?;
        let mut body = serde_json::json!({
            "FunctionId": self.config.function_id,
            "Timeout": self.config.timeout_minutes,
            "Metadata": label_map(&delegate_labels(device_key_hash, actor_omni)),
        });
        let mut merged = self.instance_envs()?;
        for (k, v) in extra_envs {
            match merged.iter_mut().find(|(mk, _)| mk == k) {
                Some(slot) => slot.1 = v.clone(),
                None => merged.push((k.clone(), v.clone())),
            }
        }
        let envs: Vec<serde_json::Value> = merged
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
        // #589 — a cold-start 408 is IN-PROGRESS, not failure: the pod keeps
        // booting past veFaaS's ~29s create budget and the error names it.
        // Adopt it once Ready (same philosophy as the precache rule: a timeout
        // is not a failure — resume, never restart). One exception, measured
        // 2026-09-18 (3 of 3 re-creates that evening): the platform DELETES
        // the booting instance — DescribeSandbox answers 404 ResourceNotFound —
        // and polling that corpse for the whole budget ends in "gave up". A
        // gone instance cannot be duplicated, so ONE fresh CreateSandbox
        // follows it (the sweeper's own retry a minute later succeeded that
        // evening; this folds that retry into the create itself).
        let mut fresh_creates_left = 1u8;
        loop {
            let v = match self.vefaas_call("CreateSandbox", body.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    let Some(id) = cold_start_instance_name(&e.to_string()) else {
                        return Err(e);
                    };
                    match self.adopt_booting_instance(&id).await {
                        Ok(id) => return Ok(id),
                        Err(AdoptError::Vanished { last }) if fresh_creates_left > 0 => {
                            fresh_creates_left -= 1;
                            tracing::warn!(
                                sandbox_id = %id,
                                last = %last,
                                "#589 cold-start resume: the booting instance is GONE (the platform \
                                 deleted it) — one fresh CreateSandbox instead of polling a corpse"
                            );
                            continue;
                        }
                        Err(err) => return Err(err.into_error(&e)),
                    }
                }
            };
            let id = v["Result"]["SandboxId"].as_str().unwrap_or_default();
            if id.is_empty() {
                bail!("CreateSandbox returned no Result.SandboxId: {v}");
            }
            return Ok(id.to_string());
        }
    }

    /// #589 — poll the instance a cold-start-timed-out `CreateSandbox` left
    /// booting, and adopt it once `Ready`. Bounded by
    /// `AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS`. Every state CHANGE is logged
    /// (the failure line used to carry only the last state, so a two-minute
    /// poll of a deleted instance read as an opaque "gave up"). Two "not
    /// found" answers in a row = the platform deleted the instance
    /// ([`AdoptError::Vanished`]) — the caller may create afresh.
    async fn adopt_booting_instance(&self, sandbox_id: &str) -> Result<String, AdoptError> {
        let budget = self.config.coldstart_wait_secs;
        if budget == 0 {
            return Err(AdoptError::Disabled);
        }
        tracing::warn!(
            sandbox_id = %sandbox_id,
            budget_secs = budget,
            "#589 CreateSandbox hit the veFaaS ~29s cold-start budget — the pod keeps booting; \
             polling DescribeSandbox to ADOPT it instead of failing (a retry would duplicate it)"
        );
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(budget as u64);
        let mut last = String::from("pending");
        let mut gone_in_a_row = 0u8;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let state = match self.describe(sandbox_id).await {
                Ok((status, _)) if status.eq_ignore_ascii_case("ready") => {
                    tracing::info!(
                        sandbox_id = %sandbox_id,
                        elapsed_s = started.elapsed().as_secs(),
                        "#589 cold-start resume: instance Ready — adopted"
                    );
                    return Ok(sandbox_id.to_string());
                }
                Ok((status, _)) => {
                    gone_in_a_row = 0;
                    status
                }
                Err(e) => {
                    let text = format!("{e:#}");
                    if describe_says_gone(&text) {
                        gone_in_a_row += 1;
                    } else {
                        gone_in_a_row = 0;
                    }
                    format!("describe error: {text}")
                }
            };
            if state != last {
                tracing::info!(
                    sandbox_id = %sandbox_id,
                    state = %state,
                    elapsed_s = started.elapsed().as_secs(),
                    "#589 cold-start resume: state"
                );
                last = state;
            }
            if gone_in_a_row >= 2 {
                return Err(AdoptError::Vanished { last });
            }
            if std::time::Instant::now() >= deadline {
                return Err(AdoptError::GaveUp {
                    budget_secs: budget.to_string(),
                    last,
                });
            }
        }
    }

    /// THE #377 entry point: give the delegate its runtime, idempotently.
    /// Reuses the delegate's live labeled instance (extending its lifetime),
    /// else creates one; at most ONE live instance per delegate ever exists.
    pub async fn ensure_for_delegate(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
    ) -> Result<EnsureOutcome> {
        self.ensure_for_delegate_with_envs(
            device_key_hash,
            actor_omni,
            &[],
            crate::sandbox_backend::no_create_envs(),
        )
        .await
    }

    /// #427 spawn-ceremony variant: same idempotent ensure, with extra envs
    /// (delegate K10 + gate relay key) merged into a CREATED instance's env.
    /// A REUSED live instance keeps its boot-time env (veFaaS can't mutate a
    /// running instance's env) — the spawn path never hits reuse in practice
    /// (a fresh device_key_hash has no prior instance), and the outcome's
    /// `created` flag tells the caller which case it got.
    pub async fn ensure_for_delegate_with_envs(
        &self,
        device_key_hash: &str,
        actor_omni: &str,
        base_envs: &[(String, String)],
        on_create: crate::sandbox_backend::CreateEnvProvider,
    ) -> Result<EnsureOutcome> {
        let _guard = self.ensure_lock.lock().await;

        let all = self.list_instances::<&str>(None).await?;
        let listed = pick_live_for_device(&all, device_key_hash).cloned();
        let mine = match listed {
            Some(m) => Some(m),
            None => self.remembered_live_instance(device_key_hash).await,
        };
        if let Some(mine) = mine {
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

        // CREATE branch — NOW mint the metered gate key (#543): on_create fires
        // only here, never on the reuse path above, so a live delegate's relay
        // key is never rotated out from under it. base_envs (identity + the
        // ceremony's eager gate envs) then the create-time gate envs.
        let created_envs = on_create().await;
        let merged: Vec<(String, String)> = base_envs.iter().cloned().chain(created_envs).collect();
        let id = self
            .create_for_delegate(device_key_hash, actor_omni, &merged)
            .await?;
        self.remember_instance(device_key_hash, &id);

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
            .list_instances(Some(&[(
                LABEL_DEVICE_KEY_HASH,
                label_value(device_key_hash),
            )]))
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
fn delegate_labels(device_key_hash: &str, actor_omni: &str) -> [(&'static str, String); 3] {
    // #543 — values are truncated to the veFaaS <64-char metadata limit.
    [
        (LABEL_DEVICE_KEY_HASH, label_value(device_key_hash)),
        (LABEL_ACTOR_OMNI, label_value(actor_omni)),
        (LABEL_MANAGED_BY, MANAGED_BY_VALUE.to_string()),
    ]
}

fn label_map<V: AsRef<str>>(labels: &[(&str, V)]) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    for (k, v) in labels {
        m.insert(
            k.to_string(),
            serde_json::Value::String(v.as_ref().to_string()),
        );
    }
    serde_json::Value::Object(m)
}

/// Normalize a veFaaS `ExpireAt` to RFC3339 — the ONE place in the system
/// that knows the vendor's timestamp shape.
///
/// **Measured live 2026-08-14** (VE prod broker, `ListSandboxes`): the API
/// emits Go's `time.Time` default `String()` layout —
/// `2026-08-15 15:50:54 +0800 CST` — NOT RFC3339. Every consumer that assumed
/// otherwise was silently wrong, in two different ways:
///
/// - the #594 lease sweeper's strict `parse_from_rfc3339` REJECTED it, so it
///   fail-closed to "no expiry" and never warm-rotated a single VE instance
///   (logged every sweep as `unparseable ExpireAt`);
/// - parent-control's `Date.parse` does NOT fail on it — V8 honors the
///   trailing zone ABBREVIATION `CST` as *US Central* (−6) and ignores the
///   authoritative `+0800`, rendering a countdown 14 h too long (a 24 h lease
///   displayed as "expires in 38h").
///
/// So the fix belongs HERE, at the boundary, not in each consumer: everything
/// downstream (`LiveRuntime`, `/v1/agent/image-status`, the sweeper, the web
/// card) reads one unambiguous shape. The numeric offset is authoritative and
/// the zone abbreviation is dropped precisely because it is ambiguous.
///
/// An unrecognized shape passes through UNCHANGED (never guessed): the sweeper
/// then refuses to rotate on it and says so, and the UI renders it verbatim —
/// both loud, neither invented.
pub(crate) fn normalize_expire_at(raw: &str) -> String {
    let t = raw.trim();
    // Empty / "?" = no expiry (an ECS task, or a row the API left blank).
    if t.is_empty() || t == "?" {
        return String::new();
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t) {
        return dt.to_rfc3339();
    }
    // Go `time.Time`: "2006-01-02 15:04:05[.fff] -0700 [MST]". Take the first
    // three whitespace tokens (date, clock, numeric offset) and drop whatever
    // trails — the zone name, or Go's `m=+0.000` monotonic suffix.
    let mut tokens = t.split_whitespace();
    if let (Some(date), Some(clock), Some(offset)) = (tokens.next(), tokens.next(), tokens.next()) {
        let core = format!("{date} {clock} {offset}");
        for fmt in [
            "%Y-%m-%d %H:%M:%S%.f %z",
            "%Y-%m-%d %H:%M:%S%.f %:z",
            "%Y-%m-%d %H:%M:%S%.f %#z",
        ] {
            if let Ok(dt) = chrono::DateTime::parse_from_str(&core, fmt) {
                return dt.to_rfc3339();
            }
        }
    }
    t.to_string()
}

/// Parse `Result.Sandboxes[]` rows. Field names per the probe's proven
/// parser (`Id`/`Status`/`ExpireAt`); `Metadata` accepted as either a string
/// map or a `[{Key,Value}]` list (the two shapes VE APIs use for maps).
/// `ExpireAt` is normalized to RFC3339 here (see [`normalize_expire_at`]) so
/// no consumer ever meets the vendor's ambiguous zone-abbreviation form.
fn parse_instances(v: &serde_json::Value) -> Vec<SandboxInstance> {
    let Some(list) = v["Result"]["Sandboxes"].as_array() else {
        return Vec::new();
    };
    list.iter()
        .map(|s| SandboxInstance {
            id: s["Id"].as_str().unwrap_or_default().to_string(),
            status: s["Status"].as_str().unwrap_or_default().to_string(),
            expire_at: normalize_expire_at(s["ExpireAt"].as_str().unwrap_or_default()),
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

/// Parse `Result.Images[]` rows (#568) — the live shape pinned in
/// [`VeFaasClient::list_sandbox_images`]'s docs.
fn parse_sandbox_images(v: &serde_json::Value) -> Vec<SandboxImage> {
    let Some(list) = v["Result"]["Images"].as_array() else {
        return Vec::new();
    };
    let s = |x: &serde_json::Value| x.as_str().unwrap_or_default().to_string();
    list.iter()
        .map(|r| SandboxImage {
            image_id: s(&r["ImageId"]),
            image_url: s(&r["ImageUrl"]),
            precache_status: s(&r["PrecacheStatus"]),
            precache_status_reason: s(&r["PrecacheStatusReason"]),
            update_time: s(&r["UpdateTime"]),
        })
        .collect()
}

/// The registration row for `image` (exact TAG-ref match — veFaaS registers
/// the URL verbatim, so no normalization beyond trim).
fn find_sandbox_image<'a>(rows: &'a [SandboxImage], image: &str) -> Option<&'a SandboxImage> {
    let want = image.trim();
    rows.iter().find(|r| r.image_url.trim() == want)
}

/// Classify a `PrecacheStatus`: `Some(true)` = preheated (console 已预热),
/// `Some(false)` = terminally failed, `None` = still in flight. Only
/// `"success"` was observed live for the happy path; the aliases keep a
/// vocabulary drift from stalling the poll, and anything unrecognized keeps
/// polling until the deadline (loud timeout, never silent success).
fn precache_terminal(status: &str) -> Option<bool> {
    let s = status.trim().to_ascii_lowercase();
    if ["success", "succeeded", "preheated"].contains(&s.as_str()) {
        Some(true)
    } else if s.contains("fail") || s.contains("error") || s == "canceled" || s == "cancelled" {
        Some(false)
    } else {
        None
    }
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
    fn config_image_comes_straight_from_cr_image() {
        // #621 — the runtime valve is gone: CR_IMAGE is THE image every spawn
        // path reads (precache, CreateSandbox, the #577 refresh).
        let cfg = VeFaasConfig::from_lookup(cfg_lookup(&[
            ("SANDBOX_FUNCTION_ID", "fn1"),
            ("SANDBOX_GATEWAY_URL", "https://gw.example"),
            ("CR_IMAGE", "cr/dsh-sandbox:v2"),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(cfg.image, "cr/dsh-sandbox:v2");
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
                // Row `a` carries the shape MEASURED on the live VE broker
                // 2026-08-14 (Go `time.Time`, not RFC3339) — normalized on the
                // way out so no consumer meets the ambiguous `CST`.
                { "Id": "a", "Status": "Ready", "ExpireAt": "2026-08-15 15:50:54 +0800 CST",
                  "Metadata": { LABEL_DEVICE_KEY_HASH: "0x11", LABEL_MANAGED_BY: MANAGED_BY_VALUE } },
                { "Id": "b", "Status": "Starting", "ExpireAt": "",
                  "Metadata": [ { "Key": LABEL_DEVICE_KEY_HASH, "Value": "0x22" } ] },
                { "Id": "c", "Status": "Failed", "ExpireAt": "" }
            ], "Total": 3 }
        });
        let rows = parse_instances(&v);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].expire_at, "2026-08-15T15:50:54+08:00");
        assert_eq!(rows[1].expire_at, "");
        assert_eq!(rows[0].metadata[LABEL_DEVICE_KEY_HASH], "0x11");
        assert_eq!(rows[1].metadata[LABEL_DEVICE_KEY_HASH], "0x22");
        assert!(rows[2].metadata.is_empty());
        assert!(rows[0].is_live() && rows[1].is_live() && !rows[2].is_live());
        // The sweeper's strict RFC3339 parse — the consumer this normalization
        // exists for — accepts the normalized value (it rejected the raw one).
        assert!(crate::lease_sweeper::parse_expire_at(&rows[0].expire_at).is_some());
    }

    /// The bug this normalization fixes, pinned end to end (measured live on
    /// the VE prod broker 2026-08-14, `ListSandboxes`).
    #[test]
    fn normalize_expire_at_converts_the_measured_go_time_layout() {
        // THE string the API actually returns, and the instant it denotes.
        let got = normalize_expire_at("2026-08-15 15:50:54 +0800 CST");
        assert_eq!(got, "2026-08-15T15:50:54+08:00");
        // Same instant as the unambiguous form — the +0800 wins, `CST` (which
        // JS `Date.parse` reads as US Central, −6) is dropped, not honored.
        assert_eq!(
            chrono::DateTime::parse_from_rfc3339(&got)
                .unwrap()
                .timestamp(),
            chrono::DateTime::parse_from_rfc3339("2026-08-15T07:50:54Z")
                .unwrap()
                .timestamp()
        );
        // Variants the vendor may emit: no zone name, fractional seconds, and
        // Go's monotonic-clock suffix.
        for raw in [
            "2026-08-15 15:50:54 +0800",
            "2026-08-15 15:50:54.123456 +0800 CST",
            "2026-08-15 15:50:54 +0800 CST m=+0.000000001",
        ] {
            let out = normalize_expire_at(raw);
            assert!(
                chrono::DateTime::parse_from_rfc3339(&out).is_ok(),
                "{raw:?} → {out:?} is not RFC3339"
            );
        }
    }

    #[test]
    fn normalize_expire_at_is_idempotent_and_never_guesses() {
        // Already-RFC3339 input (what a future API version may send) survives.
        assert_eq!(
            normalize_expire_at("2026-07-06T00:00:00+08:00"),
            "2026-07-06T00:00:00+08:00"
        );
        // "no expiry" spellings collapse to empty (the ECS/blank case).
        assert_eq!(normalize_expire_at(""), "");
        assert_eq!(normalize_expire_at("   "), "");
        assert_eq!(normalize_expire_at("?"), "");
        // An UNKNOWN shape passes through untouched — never reinterpreted into
        // a plausible-but-invented instant. Downstream then fails loud: the
        // sweeper refuses to rotate and logs the raw string.
        assert_eq!(normalize_expire_at("next tuesday"), "next tuesday");
        assert_eq!(normalize_expire_at("1786246717"), "1786246717");
        assert!(crate::lease_sweeper::parse_expire_at("next tuesday").is_none());
    }

    #[test]
    fn label_map_builds_string_object() {
        // #543 — values are 0x-stripped + truncated (short inputs pass through
        // unchanged aside from the 0x strip).
        let m = label_map(&delegate_labels("0x11", "0xaa"));
        assert_eq!(m[LABEL_DEVICE_KEY_HASH], "11");
        assert_eq!(m[LABEL_ACTOR_OMNI], "aa");
        assert_eq!(m[LABEL_MANAGED_BY], MANAGED_BY_VALUE);
    }

    #[test]
    fn parse_sandbox_images_reads_the_probed_live_shape() {
        // The EXACT response observed live 2026-07-24 (ListSandboxImages,
        // ImageType=private, broker identity) — the #568 contract pin.
        let v = serde_json::json!({
            "ResponseMetadata": { "Action": "ListSandboxImages", "Region": "cn-beijing" },
            "Result": { "Images": [ {
                "ImageGroup": "",
                "ImageId": "gqgjhemfmf",
                "ImageUrl": "agent-terrier-1-cn-beijing.cr.volces.com/agentkeys/hermes-sandbox:latest",
                "PrecacheStatus": "success",
                "PrecacheStatusReason": "",
                "UpdateTime": "2026-07-23 12:13:50.112 +0000 UTC"
            } ], "TotalCount": 1 }
        });
        let rows = parse_sandbox_images(&v);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].image_id, "gqgjhemfmf");
        assert!(rows[0].image_url.ends_with("hermes-sandbox:latest"));
        assert_eq!(rows[0].precache_status, "success");
        assert!(parse_sandbox_images(&serde_json::json!({"Result": {}})).is_empty());
    }

    #[test]
    fn find_sandbox_image_matches_exact_tag_ref() {
        let rows = vec![SandboxImage {
            image_id: "id1".into(),
            image_url: "cr.example/ns/repo:latest".into(),
            precache_status: "success".into(),
            precache_status_reason: String::new(),
            update_time: String::new(),
        }];
        assert!(find_sandbox_image(&rows, " cr.example/ns/repo:latest ").is_some());
        assert!(find_sandbox_image(&rows, "cr.example/ns/repo:other").is_none());
        // A digest ref never matches a tag registration — veFaaS cannot hold one.
        assert!(find_sandbox_image(&rows, "cr.example/ns/repo@sha256:abcd").is_none());
    }

    #[test]
    fn precache_terminal_classifies_status_vocabulary() {
        assert_eq!(precache_terminal("success"), Some(true));
        assert_eq!(precache_terminal("SUCCESS"), Some(true));
        assert_eq!(precache_terminal("failed"), Some(false));
        assert_eq!(precache_terminal("PullError"), Some(false));
        // Unknown / in-flight vocab keeps polling — timeout is the loud exit.
        // `caching` is the REAL observed in-flight value (live 2026-07-26); it
        // must classify as in-flight both to keep polling AND so the resume
        // path in refresh_precache waits on it instead of deleting it.
        assert_eq!(precache_terminal("caching"), None);
        assert_eq!(precache_terminal(""), None);
        assert_eq!(precache_terminal("running"), None);
        assert_eq!(precache_terminal("pending"), None);
    }

    #[test]
    fn image_stale_compares_registration_ids_and_tag_refs() {
        let reg = |id: &str, url: &str| SandboxImage {
            image_id: id.into(),
            image_url: url.into(),
            precache_status: "success".into(),
            precache_status_reason: String::new(),
            update_time: String::new(),
        };
        let booted = |id: &str, url: &str| InstanceImageInfo {
            registration_id: id.into(),
            source_image_url: url.into(),
        };
        let url = "cr.example/ns/repo:latest";
        // Same registration → current bits.
        assert_eq!(
            image_stale(Some(&booted("reg1", url)), Some(&reg("reg1", url))),
            Some(false)
        );
        // A refresh minted a NEW registration for the same tag → stale.
        assert_eq!(
            image_stale(Some(&booted("reg1", url)), Some(&reg("reg2", url))),
            Some(true)
        );
        // The tag ref itself moved (CR_IMAGE changed) → stale regardless of id.
        assert_eq!(
            image_stale(
                Some(&booted("reg1", url)),
                Some(&reg("reg1", "cr.example/ns/repo:v2"))
            ),
            Some(true)
        );
        // Unknowable sides stay unknown — never guessed.
        assert_eq!(image_stale(None, Some(&reg("reg1", url))), None);
        assert_eq!(image_stale(Some(&booted("reg1", url)), None), None);
        assert_eq!(image_stale(None, None), None);
    }

    #[test]
    fn label_values_fit_the_vefaas_64_char_limit() {
        // The regression this fixes: a real device_key_hash / actor_omni is a
        // 0x+64-hex, 66-char string — veFaaS rejects a Metadata VALUE ≥ 64.
        let full_hash = format!("0x{}", "a".repeat(64)); // 66 chars
        for (_, v) in delegate_labels(&full_hash, &full_hash) {
            assert!(
                v.len() < 64,
                "label value {v:?} is {} chars (must be <64)",
                v.len()
            );
        }
        // …and the truncated value still round-trips through the client match.
        let inst = SandboxInstance {
            id: "sb-x".into(),
            status: "Ready".into(),
            expire_at: String::new(),
            metadata: [
                (LABEL_DEVICE_KEY_HASH.to_string(), label_value(&full_hash)),
                (LABEL_MANAGED_BY.to_string(), MANAGED_BY_VALUE.to_string()),
            ]
            .into_iter()
            .collect(),
        };
        assert!(
            inst.labeled_for(&full_hash),
            "truncated label must still match the full hash"
        );
        assert!(!inst.labeled_for(&format!("0x{}", "b".repeat(64))));
    }
}

/// #589 — pull `X-Faas-Instance-Name: <name>` out of a `CreateSandbox`
/// `function_cold_start_timeout` 408: veFaaS names the instance it left
/// booting, and adopting it (instead of retrying) is the only duplicate-free
/// recovery — a booting instance is invisible to the reuse pre-check.
/// Why a cold-start resume ended without an adopted instance.
#[derive(Debug, PartialEq, Eq)]
enum AdoptError {
    /// `AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS=0`.
    Disabled,
    /// The budget ran out; `last` is the final observed state.
    GaveUp { budget_secs: String, last: String },
    /// DescribeSandbox answered "not found" twice in a row — the platform
    /// deleted the booting instance (measured 2026-09-18).
    Vanished { last: String },
}

impl AdoptError {
    /// The caller-facing error, with the ORIGINAL CreateSandbox failure kept
    /// verbatim (its instance name and the platform's own wording).
    fn into_error(self, cause: &anyhow::Error) -> anyhow::Error {
        match self {
            AdoptError::Disabled => anyhow::anyhow!(
                "{cause} (cold-start resume disabled: AGENTKEYS_VEFAAS_COLDSTART_WAIT_SECS=0)"
            ),
            AdoptError::GaveUp { budget_secs, last } => anyhow::anyhow!(
                "cold-start resume gave up after {budget_secs}s (last state: {last}) — original \
                 CreateSandbox error: {cause}"
            ),
            AdoptError::Vanished { last } => anyhow::anyhow!(
                "cold-start resume: the platform deleted the booting instance (last state: \
                 {last}) and a fresh create was already spent — original CreateSandbox error: \
                 {cause}"
            ),
        }
    }
}

/// A DescribeSandbox failure that means the instance no longer exists —
/// byte-for-byte the live answer of 2026-09-18: `vefaas DescribeSandbox error
/// (http 404 Not Found): Code=ResourceNotFound Message=Sandbox not found`.
fn describe_says_gone(err: &str) -> bool {
    err.contains("ResourceNotFound") || err.contains("Sandbox not found")
}

fn cold_start_instance_name(err: &str) -> Option<String> {
    if !err.contains("function_cold_start_timeout") {
        return None;
    }
    let tail = err.split("X-Faas-Instance-Name:").nth(1)?;
    let name: String = tail
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod recent_instance_tests {
    use super::remembered_instance;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    #[test]
    fn a_remembered_instance_is_offered_within_the_ttl_and_never_after() {
        let now = Instant::now();
        let mut memo = HashMap::new();
        memo.insert("abc".to_string(), ("sb-1".to_string(), now));
        let ttl = Duration::from_secs(600);
        assert_eq!(
            remembered_instance(&memo, "abc", now + Duration::from_secs(1), ttl).as_deref(),
            Some("sb-1")
        );
        assert_eq!(
            remembered_instance(&memo, "abc", now + Duration::from_secs(599), ttl).as_deref(),
            Some("sb-1")
        );
        assert_eq!(
            remembered_instance(&memo, "abc", now + Duration::from_secs(600), ttl),
            None
        );
        assert_eq!(remembered_instance(&memo, "other", now, ttl), None);
        // The knob at 0 = never offered (the old behaviour).
        assert_eq!(remembered_instance(&memo, "abc", now, Duration::ZERO), None);
    }
}

#[cfg(test)]
mod cold_start_resume_tests {
    use super::{cold_start_instance_name, describe_says_gone, AdoptError};

    #[test]
    fn a_not_found_describe_means_the_platform_deleted_the_instance() {
        // Byte-for-byte the live answer from 2026-09-18 (chef, agent-i ×2).
        let gone = "vefaas DescribeSandbox error (http 404 Not Found): Code=ResourceNotFound \
                    Message=Sandbox not found";
        assert!(describe_says_gone(gone));
        assert!(!describe_says_gone(
            "vefaas DescribeSandbox request failed: connection reset"
        ));
        assert!(!describe_says_gone("http 429 Too Many Requests"));
    }

    #[test]
    fn every_outcome_keeps_the_original_create_error() {
        let cause = anyhow::anyhow!("vefaas CreateSandbox error (http 408 Request Timeout)");
        let vanished = AdoptError::Vanished {
            last: "describe error: not found".into(),
        }
        .into_error(&cause)
        .to_string();
        assert!(
            vanished.contains("deleted the booting instance"),
            "{vanished}"
        );
        assert!(vanished.contains("http 408"), "{vanished}");
        let gave_up = AdoptError::GaveUp {
            budget_secs: "120".into(),
            last: "Pending".into(),
        }
        .into_error(&cause)
        .to_string();
        assert!(
            gave_up.contains("gave up after 120s (last state: Pending)"),
            "{gave_up}"
        );
        assert!(AdoptError::Disabled
            .into_error(&cause)
            .to_string()
            .contains("COLDSTART_WAIT_SECS=0"));
    }

    #[test]
    fn parses_the_measured_408_body() {
        // Byte-for-byte the live error from 2026-08-01 (agent-h attempt #1).
        let err = "vefaas CreateSandbox error (http 408 Request Timeout): Code=UserTimeoutError \
                   Message=load sandbox cost 29.011241119s, err msg error_code: \
                   \"function_cold_start_timeout\", error_message \"function cold start timeout, \
                   X-Faas-Instance-Name: vefaas-667unk7q-nqh31zlgbo-d9msec832hba3806hou0-sandbox\", \
                   request_id: \"\", please check fn tls log and wait instance ready.";
        assert_eq!(
            cold_start_instance_name(err).as_deref(),
            Some("vefaas-667unk7q-nqh31zlgbo-d9msec832hba3806hou0-sandbox")
        );
    }

    #[test]
    fn other_errors_do_not_resume() {
        assert_eq!(
            cold_start_instance_name("http 403 Forbidden: function_exited"),
            None
        );
        assert_eq!(
            cold_start_instance_name("function_cold_start_timeout with no instance header"),
            None
        );
    }
}
