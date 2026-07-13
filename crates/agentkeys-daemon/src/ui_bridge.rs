//! UI bridge — HTTP surface the parent-control web UI talks to.
//!
//! Distinct from `proxy.rs` (agent-facing cap-mint) and `companion.rs`
//! (second-master M-of-N approval). The ui-bridge listens on
//! `127.0.0.1:3114` by default, accepts CORS from `http://localhost:3113`
//! (the Next.js dev server / bundled web UI), and exposes operator-side
//! ceremonies the browser drives — initially K11 enrollment.
//!
//! Per arch.md §10.2, K11 enrollment is the master-binding ceremony:
//!
//!   1. browser POST /v1/k11/enroll/begin   → daemon returns
//!      PublicKeyCredentialCreationOptions (challenge + rp + user +
//!      pubKeyCredParams + authenticatorSelection)
//!   2. browser calls navigator.credentials.create(options)
//!   3. browser POST /v1/k11/enroll/finish  → daemon verifies
//!      attestation via webauthn-rs, returns credentialId
//!
//! The on-chain register (registerFirstMasterDevice) is WIRED (issue #196):
//! K11-finish shells out to `--register-master-script` and returns the real
//! `chain_tx_hash` + `chain` status (+ `chain_error` on failure). It is skipped
//! (`chain: none`) ONLY when no register script is configured (dev/no-infra) —
//! the web app launcher (`dev.sh`) always passes one, so the onboarding
//! ceremony is NOT deferred.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tower_http::cors::{Any, CorsLayer};
use url::Url;
use webauthn_rs::prelude::*;

use agentkeys_core::init_flow;

use crate::master_session::{self, MasterSessionStore, PersistedMasterSession};

/// In-flight registration state. Keyed by `user_id` (the random opaque
/// handle the browser echoes back). Cleared once a finish call consumes
/// the entry, or on next start (in-memory only).
#[derive(Default)]
pub struct EnrollState {
    pending: HashMap<String, PasskeyRegistration>,
    registered: HashMap<String, RegisteredCredential>,
}

#[derive(Clone)]
#[allow(dead_code)] // fields are read once chain submission lands in PR-C
pub struct RegisteredCredential {
    pub credential_id_b64: String,
    pub registered_at_unix: u64,
}

pub struct UiBridgeState {
    pub webauthn: Webauthn,
    pub enroll: RwLock<EnrollState>,
    pub actors: RwLock<HashMap<String, ApiActor>>,
    /// #233 actor-tree lazy-sync invalidation as a GENERATION counter, not a
    /// bool. The bool had a TOCTOU race: an in-flight EMPTY reconcile (master
    /// not yet registered) could latch `synced` AFTER a master-register
    /// invalidation and permanently mask the new master row — the empty
    /// actor-page bug. `fleet_gen` is bumped by every fleet-mutating handler
    /// (register / reset / pairing / accept / scope / revoke) via
    /// [`invalidate_fleet_sync`]; `fleet_synced_gen` is the generation the
    /// in-memory `actors` map was last reconciled to. A reconcile only advances
    /// `fleet_synced_gen` to the generation it OBSERVED before reading the
    /// chain, so a stale reconcile can never hide a newer invalidation.
    pub fleet_gen: std::sync::atomic::AtomicU64,
    pub fleet_synced_gen: std::sync::atomic::AtomicU64,
    /// Serializes fleet reconciles so concurrent `/v1/actors` reads don't each
    /// hit the chain or race on the actor map (#233 hardening).
    pub fleet_sync_lock: tokio::sync::Mutex<()>,
    pub caps: RwLock<HashMap<String, Vec<ApiCapToken>>>,
    pub audit: RwLock<VecDeque<ApiAuditEvent>>,
    pub audit_tx: broadcast::Sender<ApiAuditEvent>,
    pub workers: RwLock<HashMap<String, ApiWorker>>,
    pub anchor: RwLock<ApiAnchorStatus>,
    /// Master-actor memory entries, keyed by content_hash for idempotent
    /// plant (re-planting the same entry is a no-op). Maps the §2 "plant
    /// preserved memory" flow + GH plan issue-9step-flow.md.
    pub master_memory: RwLock<HashMap<String, ApiMemoryEntry>>,
    /// Serializes real-chain plants (#201 Phase 4, codex finding 1). The plant is
    /// a read-modify-write of each `memory:<ns>` blob; two concurrent plants for
    /// the same namespace would otherwise race (both read, both write → last wins,
    /// dropping the other's entries). Held for the whole real-chain plant body.
    pub plant_lock: tokio::sync::Mutex<()>,
    /// In-memory mirror of the authored memory-types taxonomy (#207 item 1A,
    /// config-init entry point A). On the REAL chain the durable
    /// `config/memory-taxonomy.enc` is the source of truth and this is just a
    /// write-through cache; with Config UNCONFIGURED (dev / no-infra) it is the
    /// only home, so `init` still authors a taxonomy and the master-memory list
    /// can show its categories before any memory is planted. `None` until the
    /// master picks a preset (or NL→COMPILE, #207 item 1B, lands).
    pub authored_taxonomy: RwLock<Option<MemoryTaxonomy>>,
    /// #408 — the accept card's FINAL grant set + `is_device` flag, stashed by
    /// `accept_build_proxy` keyed by `request_id` and consumed by `ack_pairing`,
    /// so the freshly-surfaced actor row carries the service NAMES the operator
    /// actually approved (the on-chain scope stores only keccak ids — names are
    /// unrecoverable from chain). In-memory only: after a daemon restart a
    /// chain-reconstructed row falls back to hash-only display; the mirror's
    /// preserve semantics (`scope_unknown_service_ids`) are untouched either way.
    pub accept_grants_by_request: RwLock<HashMap<String, (Vec<String>, bool)>>,
    /// #404 — the master's channel registry (id-anchored channel definitions),
    /// taxonomy-style: the durable home is the Config-class doc
    /// `config/channel-registry.enc` and this is a write-through cache; with
    /// Config UNCONFIGURED (dev / no-infra) it is the only home (mutations then
    /// report `storage:"cached"`). `None` until first load.
    pub channel_registry: RwLock<Option<ChannelRegistry>>,
    /// #424 — the binding manifest: per bound actor, the readable pairing
    /// metadata the chain deliberately does NOT store (label, delegate-vs-device
    /// kind, granted service NAMES). Durable home is the Config-class doc
    /// `config/binding-manifest.enc`; this is a write-through cache (taxonomy
    /// posture — cache-only when Config is unconfigured). Written on accept +
    /// scope commit; read by the #233 fleet reconcile so a device survives a
    /// daemon restart with its kind + channel chips intact.
    pub binding_manifest: RwLock<Option<BindingManifest>>,
    /// #427 — the spawn/archive ceremony stash: `device_key_hash` (from the
    /// broker build response) → the ceremony context (label, preset, memory
    /// namespace, template service names / keep-choice), consumed by the
    /// matching submit proxy on a CONFIRMED ceremony to write the binding-
    /// manifest row. In-memory only, same posture as the accept stash above.
    pub ceremony_context_by_dkh: RwLock<HashMap<String, serde_json::Value>>,
    /// #424 — the scope-commit stash: `user_op_hash` (from `/v1/scope/build`) →
    /// `(actor_omni, services)`, consumed by `scope_submit_proxy` on a confirmed
    /// commit to upsert the binding manifest with the NAMES the set-replace
    /// actually granted (the chain stores only keccak ids).
    pub scope_services_by_op_hash: RwLock<HashMap<String, (String, Vec<String>)>>,
    /// #424 — once-per-process latch for the gateway contact-registry reconcile
    /// (migrate-up / restore-down against the Config-class doc), run on the
    /// first contacts read so a rebuilt gateway host self-heals.
    pub gateway_registry_synced: std::sync::atomic::AtomicBool,
    /// Broker base URL for the W1 onboarding email→verify flow. `None` ⇒ email
    /// onboarding is disabled (the daemon was started without `--broker-url`)
    /// and the email endpoints fail closed with `broker-not-configured`.
    pub broker_url: Option<String>,
    /// The operator's stack inventory (#373): every known (chain, broker) pair,
    /// parsed once at boot from `AGENTKEYS_STACKS_JSON` (the fleet console
    /// derives it from the `scripts/operator-workstation*.env` files and injects
    /// it into the local web-app job — data-driven end to end, no endpoint is
    /// hardcoded). Backs `GET /v1/stack/list` for the web stack selector.
    /// Empty ⇒ the endpoint synthesizes a single entry from the daemon's own
    /// (chain, broker), so a bare `dev.sh` run still renders truthfully.
    pub stacks: Vec<StackEntry>,
    /// Allowed browser origin (= the CORS origin, e.g. `http://localhost:3113`).
    /// Server-side defense-in-depth: the onboarding email endpoints reject a
    /// mismatched `Origin` header even though browser CORS already would, so a
    /// cross-origin page can't trigger magic-link emails.
    pub allowed_origin: String,
    /// W1 onboarding: request_id → email, recorded at email/start so email/status
    /// knows which identity verified. Cleared on logout.
    pub pending_email: RwLock<HashMap<String, String>>,
    /// The verified operator identity, held in the daemon once the magic link is
    /// clicked (never handed to the browser — the daemon is the authenticated
    /// proxy). `None` until verified / after logout; this is the real "logged in"
    /// signal that replaces the browser's `ak_onboarded` localStorage flag.
    pub onboarding_session: RwLock<Option<OnboardingSession>>,
    /// Signer (dev_key_service) base URL for the SIWE→J1 step — the signer
    /// *attests* the managed wallet it derives (no user wallet / MetaMask).
    /// `None` ⇒ email verify holds an identity-only session (no EVM J1 / actor omni).
    pub signer_url: Option<String>,
    /// Chain id for the managed-wallet attestation (mirrors `--init-chain-id`).
    pub chain_id: u64,
    /// #418 — the WeChat gateway worker base URL (`AGENTKEYS_WORKER_WEIXIN_URL`).
    /// `None` ⇒ the `/v1/master/gateway/*` proxies fail closed
    /// (`gateway-not-configured`).
    pub weixin_gateway_url: Option<String>,
    /// #418 — the gateway admin bearer (`AGENTKEYS_WEIXIN_ADMIN_TOKEN`, copied
    /// by the operator from the broker's weixin-secrets.env). Injected
    /// server-side on every gateway proxy call — the browser NEVER sees it.
    pub weixin_admin_token: Option<String>,
    /// W3 real-memory chain — the memory worker base URL (e.g. `https://memory.example.invalid`).
    /// `None` ⇒ master-memory plant/list fall back to the in-memory store (dev/no-infra).
    pub memory_url: Option<String>,
    /// Per-actor memory IAM role ARN for the STS relay (`MEMORY_ROLE_ARN`). Required
    /// alongside `memory_url` for the real chain; a partial config fails loud (issue #90 discipline).
    pub memory_role_arn: Option<String>,
    /// #201 config data class — the config worker base URL (e.g. `https://config.example.invalid`).
    /// `None` ⇒ the memory-types taxonomy is read/written from the in-memory fallback (dev/no-infra),
    /// and the master-memory list derives categories from the cache instead of the durable,
    /// master-only Config-class taxonomy object (`config/memory-taxonomy.enc`).
    pub config_url: Option<String>,
    /// #201 config data class — per-actor config IAM role ARN for the STS relay (`CONFIG_ROLE_ARN`).
    /// Required alongside `config_url`; a partial config fails loud (issue #90 discipline).
    pub config_role_arn: Option<String>,
    /// #207 classifier-service — the classify worker base URL. `Some` ⇒ the
    /// cap-gated, audited worker TAG path (mint a `Classify` cap → `/v1/classify/tag`);
    /// `None` ⇒ the daemon classifies against the bundled `agentkeys-catalog` tier-0
    /// locally (deterministic, dev/no-infra). Drives cred auto-categorize (#207 item 7)
    /// + connect-time auto-distribute (#207 item 5).
    pub classify_url: Option<String>,
    /// #390 — the bound agent's sandbox BRIDGE base URL (hermes_bridge.py,
    /// e.g. `http://127.0.0.1:8090`): the persona/context apply + restart
    /// target. `None` ⇒ persona edits still persist canonically but report
    /// `applied: false` (`sandbox_unconfigured`), and the restart verb 503s.
    /// Today ONE configured sandbox (the L1/L2 single-sandbox topology);
    /// per-delegate routing arrives with spawn-on-pair.
    pub sandbox_bridge_url: Option<String>,
    /// #390 — bearer for the sandbox bridge (`AGENTKEYS_BRIDGE_TOKEN` on the
    /// bridge side). `None` ⇒ requests are sent unauthenticated (the bridge's
    /// dev mode).
    pub sandbox_bridge_token: Option<String>,
    /// #97 — the audit worker the decode view fetches REAL envelopes from
    /// (by the submit receipt hashes on feed events). `None` ⇒ the decode
    /// stays a synthesized preview (dev / no-infra / tests).
    pub audit_worker_url: Option<String>,
    /// AWS region for the STS relay (`REGION`).
    pub region: String,
    /// The on-chain-registered master device key hash, sent as `device_key_hash` in
    /// memory cap-mint. Must match the device registered via the W3 bootstrap
    /// (`docs/plan/web-flow/w3-real-memory.md` §4). `None` ⇒ real chain disabled.
    /// Issue #196 makes this a FALLBACK: once the K11-finish register shell-out
    /// runs, `registered_master` holds the freshly-registered hash and takes
    /// precedence, so the operator no longer has to pass `--master-device-key-hash`.
    pub master_device_key_hash: Option<String>,
    /// Issue #196: the on-chain master-device registration result, populated by
    /// the K11-finish handler's register shell-out. `Some` ⇒ the master device is
    /// on chain with CAP_MINT; its `device_key_hash` is what real cap-mint sends
    /// (takes precedence over `master_device_key_hash`).
    pub registered_master: RwLock<Option<RegisteredMaster>>,
    /// Issue #196: path to `e2e/scripts/heima-register-first-master.sh` (the
    /// §4.2 sanctioned shell-out). `None` ⇒ K11-finish does NOT submit the
    /// on-chain register (chain stays "none"); set via `--register-master-script`
    /// to enable the real web onboarding chain write.
    pub register_master_script: Option<String>,
    /// Resolved chain profile (deployed contract registry + explorer + RPC) the
    /// chain-info + audit-decode endpoints serve to the web UI (#153). Resolved
    /// from `$AGENTKEYS_CHAIN` (default `heima`) at `build_state`.
    pub chain_profile: agentkeys_core::chain_profile::ChainProfile,
    /// Issue #220: the on-disk master-session store rooted at `~/.agentkeys/`.
    /// `Some` ⇒ the master session coordinates persist across daemon restarts and
    /// rehydrate on startup; `None` ⇒ persistence disabled (tests, or no `$HOME`).
    pub master_session_store: Option<MasterSessionStore>,
    /// Issue #220: the durable master session coordinates, in memory. Mirrors what
    /// was persisted (or rehydrated) — present whether or not the J1 is still valid
    /// (an expired record drives the `session: "expired"` re-auth signal without
    /// re-onboarding). Distinct from `onboarding_session`, which is set ONLY while
    /// the J1 is live (the "actively logged in" signal).
    pub master_session: RwLock<Option<PersistedMasterSession>>,
    /// #225 / E7: the master register is two-phase (the browser passkey signs the
    /// register UserOp BETWEEN build + submit). K11-finish runs the `build`
    /// (deploy the P256Account + assemble the register UserOp) and stashes the
    /// build context HERE; `POST /v1/master/register/submit` consumes it after the
    /// browser signs `userop_hash`. `None` ⇒ no register in flight. Single-master,
    /// so one slot suffices.
    pub pending_register: RwLock<Option<PendingMasterRegister>>,
}

/// #225 / E7: build-phase output of the two-phase master register, held between
/// `/v1/k11/enroll/finish` (build) and `/v1/master/register/submit`.
#[derive(Clone, Debug)]
pub struct PendingMasterRegister {
    /// `erc4337-register-master.sh build` state file (ACCOUNT/NONCE/CALLDATA/…),
    /// read back by the `submit` sub-command. Empty on the #278 D6 broker path.
    pub state_file: String,
    /// #278 D6: the broker `/v1/register/build` `WireUserOp` (with the non-empty
    /// `initCode`). `Some` ⇒ submit forwards to the broker `/v1/register/submit`
    /// (one sponsored op); `None` ⇒ the legacy deployer-funded shell-out path.
    pub broker_user_op: Option<serde_json::Value>,
    /// The deployed/predicted P256Account (the operatorMasterWallet-to-be).
    pub account: String,
    /// `master_cred_id_hash(omni)` — the account's signer key + a submit arg.
    pub cred_id_hash: String,
    /// `keccak(operator_omni)` — what cap-mint sends once registered.
    pub device_key_hash: String,
    /// The session omni the master registers under.
    pub operator_omni: String,
}

/// Issue #196: outcome of the on-chain master-device registration shell-out.
#[derive(Clone, Debug)]
pub struct RegisteredMaster {
    /// `device_key_hash` the broker resolves on cap-mint — what `real_memory_ctx`
    /// sends. Derived + returned by `heima-register-first-master.sh`.
    pub device_key_hash: String,
    /// The session (managed-wallet) omni the device was registered under
    /// (operator == actor for master-self). `cap.rs` requires
    /// `device.actor_omni == req.actor_omni`, so this must equal the cap-mint omni.
    pub operator_omni: String,
    /// `registerFirstMasterDevice` tx hash. `None` on idempotent skip (the device
    /// was already on chain from a prior login).
    pub tx_hash: Option<String>,
    /// #225 / E7: the master's on-chain P256Account address (`operatorMasterWallet[omni]`),
    /// surfaced on the actor page. `None` for a pre-E7 / EOA-bound master.
    pub account: Option<String>,
}

// The plant wire contract (route + `ApiMemoryEntry` + request/response bodies)
// is OWNED by the wasm-safe `agentkeys-protocol::web_api` (#275 tier-3): the
// browser host compiles the same types via `agentkeys-web-core`, so the
// frontend can no longer hand-build a drifted body. Re-exported here so the
// daemon-internal paths (and the fixture-pinning test below) keep their names.
pub use agentkeys_backend_client::protocol::web_api::{
    ApiMemoryEntry, MasterMemoryPlantRequest, MasterMemoryPlantResponse, MASTER_MEMORY_PLANT_ROUTE,
};
// #390 — the typed-context substrate (kind + the reserved persona namespace),
// owned by the same wasm-safe protocol crate.
pub use agentkeys_backend_client::protocol::{
    normalize_omni_0x, persona_soul_key, ContextKind, PERSONA_NAMESPACE,
};

/// Content hash over (ns ‖ key ‖ body) — the dedup key for plant idempotency
/// AND the durable-merge identity (codex finding 1). A free function so the
/// merge can recompute it for durable `StoredMemoryEntry`s (which don't carry
/// the hash) using the same scheme as `ApiMemoryEntry::compute_hash`.
fn content_hash_for(ns: &str, key: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ns.as_bytes());
    h.update(b"\x1f");
    h.update(key.as_bytes());
    h.update(b"\x1f");
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

/// Daemon-side helpers on the SHARED wire type: inherent impls are only legal
/// in the defining crate (`agentkeys-protocol`), and these touch daemon-local
/// concerns (the sha256 dedup scheme + the private on-disk
/// [`StoredMemoryEntry`] form), so they ride an extension trait here — call
/// sites read exactly as before.
trait ApiMemoryEntryExt: Sized {
    fn compute_hash(&self) -> String;
    /// The on-disk form stored inside the per-namespace JSON array (#201 Phase 4).
    fn to_stored(&self) -> StoredMemoryEntry;
    /// Rehydrate a UI entry from a stored array element decrypted out of
    /// `memory:<ns>.enc`. `version`/`preview` are derived (not stored) and
    /// `content_hash` is left empty (the read path doesn't dedup).
    fn from_stored(ns: &str, s: StoredMemoryEntry) -> Self;
}

impl ApiMemoryEntryExt for ApiMemoryEntry {
    fn compute_hash(&self) -> String {
        content_hash_for(&self.ns, &self.key, &self.body)
    }

    fn to_stored(&self) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: self.key.clone(),
            title: self.title.clone(),
            body: self.body.clone(),
            updated: self.updated.clone(),
            bytes: self.bytes,
            version: self.version.clone(),
            kind: self.kind,
        }
    }

    fn from_stored(ns: &str, s: StoredMemoryEntry) -> Self {
        let preview = s.body.chars().take(80).collect();
        ApiMemoryEntry {
            ns: ns.to_string(),
            key: s.key,
            title: s.title,
            bytes: s.bytes,
            version: s.version,
            updated: s.updated,
            preview,
            body: s.body,
            content_hash: String::new(),
            kind: s.kind,
        }
    }
}

fn default_stored_version() -> String {
    "v1".to_string()
}

/// One element of the per-namespace JSON array `memory:<ns>.enc` (#201 Phase 4).
/// Fixes the lossy single-body overwrite: a namespace with several memories
/// round-trips as one array. The agent reads the same blobs (W4 inheritance
/// defers the agent WRITE path; the inject already renders this shape).
/// `version` + `kind` (#390) are serde-defaulted so pre-#390 blobs decode
/// unchanged (`v1` / `knowledge`); the persona namespace relies on both for
/// its durable version history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StoredMemoryEntry {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) body: String,
    pub(crate) updated: String,
    pub(crate) bytes: u64,
    #[serde(default = "default_stored_version")]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) kind: ContextKind,
}

/// The `config/memory-taxonomy.enc` object (#178 §7 / #201): the master-only
/// category set the web list resolves WITHOUT decrypting any memory blob. The
/// categories are the namespaces the operator has planted; labels are derived.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryTaxonomy {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    categories: Vec<MemoryCategory>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct MemoryCategory {
    pub ns: String,
    pub label: String,
}

/// The signed `service` of the Config-class taxonomy object (→ S3 key
/// `bots/<O_master>/config/memory-taxonomy.enc`). Config is master-only, so the
/// broker + worker skip the on-chain scope check for `operator == actor` (#195).
const TAXONOMY_SERVICE: &str = "memory-taxonomy";

/// The signed `service` of the Config-class CHANNEL REGISTRY object (→ S3 key
/// `bots/<O_master>/config/channel-registry.enc`) — the master-curated catalog
/// of channel definitions (#404). This is the "registry-from-config-data-class
/// sync" the channel worker crate docs deferred: the worker/broker stay
/// grant-anchored (a channel id is free-form at the chain layer); the registry
/// is the MASTER's bookkeeping — which ids exist, their display names — so the
/// web app can offer selection instead of silent free-text creation, and the
/// daemon can re-name on-chain grant hashes after a restart.
const CHANNEL_REGISTRY_SERVICE: &str = "channel-registry";

/// One channel DEFINITION in the master's registry (#404). `id` is the
/// IMMUTABLE anchor — it is the exact string hashed into the on-chain
/// `channel-pub:<id>` / `channel-sub:<id>` service ids, so it can never be
/// renamed (rename = a different channel). `name`/`note` are display-only and
/// freely editable.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiChannel {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub note: Option<String>,
    #[ts(type = "number")]
    pub created_at: u64,
}

/// The durable registry doc (config-class, master-only). Version field for
/// forward evolution; the vec is small (a household's channel count).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelRegistry {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    channels: Vec<ApiChannel>,
}

/// The signed `service` of the Config-class BINDING MANIFEST object (→ S3 key
/// `bots/<O_master>/config/binding-manifest.enc`) — #424 §1. Per bound actor it
/// records what the chain deliberately does NOT (no PII, no per-edit gas):
/// label, delegate-vs-device kind, and the granted service NAMES. On-chain both
/// kinds bind as `TIER_AGENT` rows (`registerAgentDevice`) and scope is keccak
/// hashes, so after a daemon restart the kind + names are unrecoverable from
/// chain alone; the manifest is the deterministic off-chain dictionary the #233
/// reconcile hydrates from (the channel-registry hash-match stays as SECONDARY
/// enrichment for grants the manifest predates).
const BINDING_MANIFEST_SERVICE: &str = "binding-manifest";

/// The signed `service` of the Config-class GATEWAY CONTACT REGISTRY object
/// (→ S3 key `bots/<O_master>/config/gateway-contact-registry.enc`) — #424 §2.
/// The durable, master-only copy of the WeChat gateway's contact registry; the
/// gateway-host file stays the working cache. The daemon write-throughs it on
/// every mutating gateway admin proxy and restores it to an EMPTY (rebuilt)
/// gateway on the first contacts read.
const GATEWAY_CONTACTS_SERVICE: &str = "gateway-contact-registry";

/// One bound actor's readable pairing metadata (#424 §1). `actor_omni` +
/// `device_key_hash` anchor the entry to the on-chain `SidecarRegistry` row;
/// everything else is the readable layer the chain never stores.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BindingManifestEntry {
    /// `0x`+64-hex actor omni (normalized lowercase) — the join key against
    /// `DeviceEntry.actorOmni` at reconcile time.
    pub actor_omni: String,
    /// `0x`+64-hex on-chain device key hash (secondary join key).
    #[serde(default)]
    pub device_key_hash: String,
    /// The pairing label the accept card showed (`ApiActor.label`).
    pub label: String,
    /// `"device"` (channel-endpoint, §14.10) or `"delegate"` (sandbox-resident).
    pub kind: String,
    /// The service NAMES the operator actually granted (`channel-pub:<id>`,
    /// `memory:<ns>`, `cred:<service>`, …) — the readable twin of the on-chain
    /// keccak scope set.
    #[serde(default)]
    pub granted_service_names: Vec<String>,
    /// Unix seconds of the last upsert (accept or scope commit).
    #[serde(default)]
    pub updated_at: u64,
    /// #427 — the preset the delegate was spawned from (`""`/absent = blank
    /// spawn or a pre-#427 binding). Readable-layer only, like `label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset_id: Option<String>,
    /// #427 — the delegate's `memory:<ns>` namespace name (the #425 O2
    /// inheritance-discovery key; grants on-chain are keccak ids).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_ns: Option<String>,
    /// #427 — set when the delegate was ARCHIVED. The row is retained (epic
    /// acceptance: manifest + audit rows survive the archive) so a kept
    /// namespace stays discoverable for a successor spawn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<u64>,
    /// #427/#425 O4 — the operator's keep-vs-delete choice at archive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_kept: Option<bool>,
}

/// The durable manifest doc (config-class, master-only). Small: one entry per
/// bound actor in the household fleet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindingManifest {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    bindings: Vec<BindingManifestEntry>,
}

/// Bare-hex lowercase form for manifest joins — lowercase FIRST so `0X` strips
/// too (`normalize_omni_0x` only guarantees a prefix, not case).
fn manifest_norm(s: &str) -> String {
    let lower = s.trim().to_lowercase();
    lower.trim_start_matches("0x").to_string()
}

impl BindingManifest {
    /// Look up an entry by actor omni (primary) or device key hash (secondary),
    /// both compared 0x-normalized lowercase.
    pub fn entry_for(
        &self,
        actor_omni: &str,
        device_key_hash: &str,
    ) -> Option<&BindingManifestEntry> {
        let (a, d) = (manifest_norm(actor_omni), manifest_norm(device_key_hash));
        self.bindings
            .iter()
            .find(|e| manifest_norm(&e.actor_omni) == a)
            .or_else(|| {
                if d.is_empty() {
                    return None;
                }
                self.bindings.iter().find(|e| {
                    !e.device_key_hash.is_empty() && manifest_norm(&e.device_key_hash) == d
                })
            })
    }

    /// Every manifest row (read view — #429 inheritance bookkeeping etc.).
    pub fn entries(&self) -> &[BindingManifestEntry] {
        &self.bindings
    }

    /// Upsert by actor omni (0x-normalized). An existing entry keeps its `kind`
    /// unless the incoming entry states one explicitly — a scope re-grant must
    /// never silently flip a device into a delegate.
    pub fn upsert(&mut self, mut entry: BindingManifestEntry) {
        entry.actor_omni = format!("0x{}", manifest_norm(&entry.actor_omni));
        if !entry.device_key_hash.is_empty() {
            entry.device_key_hash = format!("0x{}", manifest_norm(&entry.device_key_hash));
        }
        match self
            .bindings
            .iter_mut()
            .find(|e| manifest_norm(&e.actor_omni) == manifest_norm(&entry.actor_omni))
        {
            Some(existing) => {
                if entry.kind.is_empty() {
                    entry.kind = existing.kind.clone();
                }
                if entry.label.is_empty() {
                    entry.label = existing.label.clone();
                }
                if entry.device_key_hash.is_empty() {
                    entry.device_key_hash = existing.device_key_hash.clone();
                }
                // #427 readable-layer fields survive an upsert that doesn't
                // state them (a scope re-grant must not wipe the spawn record).
                if entry.preset_id.is_none() {
                    entry.preset_id = existing.preset_id.clone();
                }
                if entry.memory_ns.is_none() {
                    entry.memory_ns = existing.memory_ns.clone();
                }
                if entry.archived_at.is_none() {
                    entry.archived_at = existing.archived_at;
                }
                if entry.resources_kept.is_none() {
                    entry.resources_kept = existing.resources_kept;
                }
                *existing = entry;
            }
            None => {
                if entry.kind.is_empty() {
                    // A scope commit on an actor the manifest never saw — derive
                    // the kind with the SAME predicate the accept card / D9
                    // spawn gate use (all-channel grants = device).
                    let joined = entry.granted_service_names.join(" ");
                    entry.kind =
                        if agentkeys_backend_client::protocol::scope_is_device_only(&joined) {
                            "device".into()
                        } else {
                            "delegate".into()
                        };
                }
                self.bindings.push(entry);
            }
        }
    }
}

/// Channel-id shape: the on-chain anchor must be stable + lowercase (service
/// ids are keccak'd over the LOWERCASED string on every path), and short enough
/// to read on a device card. Mirrors the label discipline elsewhere.
fn valid_channel_id(id: &str) -> bool {
    let n = id.len();
    (1..=48).contains(&n)
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

/// Title-case a namespace for its display label (`travel` → `Travel`). The
/// taxonomy object is the durable label home; this is the derivation used when
/// minting a fresh taxonomy from planted namespaces.
fn label_for_ns(ns: &str) -> String {
    let mut chars = ns.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Union `incoming` categories INTO `existing`, keyed by namespace, preserving
/// every existing entry (its label is kept — an authored label or a user edit is
/// never clobbered) and appending only namespaces not already present. Sorted by
/// ns for a stable on-disk blob.
///
/// This is what makes an **authored** taxonomy (#207 item 1A) durable against the
/// test-only `plant`: re-running `init` is an idempotent no-op, and a later plant
/// (cache-derived categories) ADDS its namespaces but can never drop the authored
/// ones — the same read-modify-write discipline already applied to memory blobs
/// (#201 codex finding 1), now applied to the category index.
fn merge_categories(
    existing: Vec<MemoryCategory>,
    incoming: &[MemoryCategory],
) -> Vec<MemoryCategory> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut out: Vec<MemoryCategory> = Vec::new();
    for c in existing {
        if seen.insert(c.ns.clone()) {
            out.push(c);
        }
    }
    for c in incoming {
        if seen.insert(c.ns.clone()) {
            out.push(c.clone());
        }
    }
    out.sort_by(|a, b| a.ns.cmp(&b.ns));
    out
}

/// Parse a decrypted `memory:<ns>` blob into its entries, tolerating BOTH the
/// new per-namespace JSON array (#201 Phase 4) and a legacy single-body blob
/// (pre-#201 / agent-written) — the latter becomes a one-element array keyed by
/// the namespace, so the read path never breaks on an old blob.
fn parse_stored_blob(plaintext: &str, ns: &str) -> Vec<StoredMemoryEntry> {
    let trimmed = plaintext.trim_start();
    if trimmed.starts_with('[') {
        if let Ok(entries) = serde_json::from_str::<Vec<StoredMemoryEntry>>(plaintext) {
            return entries;
        }
    }
    vec![StoredMemoryEntry {
        key: ns.to_string(),
        title: ns.to_string(),
        body: plaintext.to_string(),
        updated: String::new(),
        bytes: plaintext.len() as u64,
        version: default_stored_version(),
        kind: ContextKind::Knowledge,
    }]
}

/// Merge the DURABLE entries already stored in a namespace with the newly
/// planted entries, deduped by content hash (ns‖key‖body). Durable entries are
/// ALWAYS preserved (codex finding 1 — a plant must never drop already-stored
/// memory); a new entry whose content matches an existing one is a no-op,
/// otherwise it is appended. Sorted by key for a stable on-disk blob. Returns
/// the merged array plus the count of entries that were genuinely new to the
/// durable set (for the plant's `planted`/`skipped` accounting).
fn merge_stored_entries(
    ns: &str,
    durable: Vec<StoredMemoryEntry>,
    incoming: &[ApiMemoryEntry],
) -> (Vec<StoredMemoryEntry>, usize) {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out: Vec<StoredMemoryEntry> = Vec::new();
    for d in durable {
        if seen.insert(content_hash_for(ns, &d.key, &d.body)) {
            out.push(d);
        }
    }
    let mut newly_added = 0usize;
    for e in incoming {
        if seen.insert(content_hash_for(ns, &e.key, &e.body)) {
            out.push(e.to_stored());
            newly_added += 1;
        }
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    (out, newly_added)
}

pub type SharedUiBridgeState = Arc<UiBridgeState>;

const AUDIT_BUFFER_CAP: usize = 200;

#[derive(Clone, Debug, Default, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiScopeBits {
    /// `memory:<ns>` granted — the delegate may READ the master's shared canonical
    /// memory for this namespace (#295 distribution). The delegate's OWN local
    /// memory is its own and is not represented here.
    pub read: bool,
    /// `inbox:<ns>` granted — the delegate may WRITE/suggest into the master's
    /// absorption inbox for this namespace (#339), which the master curates. A
    /// DISTINCT on-chain grant (`keccak("inbox:<ns>") != keccak("memory:<ns>")`), so
    /// granting read never grants write — and the delegate NEVER writes the master's
    /// shared memory directly (the only contribution path is the curated inbox).
    pub write: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiPaymentCap {
    pub per_tx: f64,
    pub daily: f64,
    pub currency: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiTimeWindow {
    pub start: String,
    pub end: String,
    pub tz: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiActor {
    pub id: String,
    pub omni: String,
    pub omni_hex: String,
    pub label: String,
    pub role: String,
    pub parent: Option<String>,
    pub derivation: String,
    pub device: String,
    pub device_pubkey: String,
    pub last_active: String,
    pub status: String,
    pub vendor: String,
    pub k11: bool,
    /// #233/#243: the on-chain `SidecarRegistry` device key hash (`0x` + 64 hex)
    /// when known — set for chain-reconstructed actors and fresh pairings. Lets
    /// the master-reset fleet teardown revoke by hash even when the per-label
    /// `~/.agentkeys/agents/<label>.json` record never existed on this machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub device_key_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope: Option<HashMap<String, ApiScopeBits>>,
    /// #248: on-chain scope service ids (0x-hex keccak) that aren't a known
    /// `memory:<ns>` — e.g. `cred:<service>` granted at accept. The panel's
    /// set-replace commit echoes these back so a memory toggle can't wipe them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope_unknown_service_ids: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub payment_cap: Option<ApiPaymentCap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub time_window: Option<ApiTimeWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub services: Option<Vec<String>>,
    /// #225 E7 actor page: the actor's on-chain account. master → its passkey
    /// P256Account when bound (absent when unbound); agent → its K10 device
    /// omni. Set by `enrich_actor_account` on the actors read path — struct
    /// fields (not ad-hoc JSON inserts) so the generated TS contract carries
    /// them (B2 rung 3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub account_address: Option<String>,
    /// "p256account" (bound master) | "none" (unbound master → register CTA) |
    /// "device" (agent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub account_type: Option<String>,
    /// #429 — the preset the delegate was spawned from (#424 manifest
    /// readable layer). Absent for devices/masters/pre-#427 bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub preset_id: Option<String>,
    /// #429 — the delegate's `memory:<ns>` namespace name (manifest layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub memory_ns: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiCapToken {
    pub id: String,
    pub cap: String,
    pub scope: String,
    pub ttl: String,
    pub minted: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub danger: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiAuditEvent {
    pub id: String,
    pub ts: String,
    pub actor_id: String,
    pub actor: String,
    pub kind: String,
    pub detail: String,
    pub chip: String,
    pub sev: String,
    /// #97: the confirmed on-chain tx for control-plane ops (accept / scope /
    /// revoke submits). `None` for synthesized / local events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tx_hash: Option<String>,
    /// #97: the `AuditEnvelope v1` receipt hashes the broker emitted for this
    /// op — the decode view fetches the REAL envelopes by these instead of
    /// synthesizing a preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub audit_envelope_hashes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiWorkerActorShare {
    pub actor: String,
    #[ts(type = "number")]
    pub count: u64,
    pub share: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiWorker {
    pub id: String,
    pub title: String,
    pub host: String,
    pub desc: String,
    #[ts(type = "number")]
    pub calls_today: u64,
    #[ts(type = "number")]
    pub calls_hour: u64,
    #[ts(type = "number")]
    pub p50: u64,
    #[ts(type = "number")]
    pub p95: u64,
    pub cap: String,
    pub by_actor: Vec<ApiWorkerActorShare>,
}

/// #339 P2 — one absorption-inbox proposal in the master's curate queue. The
/// frontend-facing view of `agentkeys_protocol::InboxItemMeta`; `source_delegate_omni`
/// + `ns` are worker-stamped (the delegate cannot forge its own attribution).
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiInboxItem {
    pub s3_key: String,
    pub source_delegate_omni: String,
    pub ns: String,
    pub key: String,
    pub content_hash: String,
    #[ts(type = "number")]
    pub bytes: u64,
    #[ts(type = "number")]
    pub ts: u64,
    /// #390 — the delegate-labeled, worker-stamped context kind; drives the
    /// per-kind curate gate in the UI (skill = view-before-accept, persona =
    /// never adoptable). Absent on pre-#390 items = `knowledge`.
    #[serde(default)]
    pub kind: ContextKind,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiAnchorBatch {
    pub ts: String,
    pub root: String,
    #[ts(type = "number")]
    pub count: u64,
    pub txn: String,
    #[ts(type = "number")]
    pub conf: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiAnchorStatus {
    #[ts(type = "number")]
    pub last_anchor_at: u64,
    #[ts(type = "number")]
    pub next_anchor_in: u64,
    pub recent: Vec<ApiAnchorBatch>,
}

#[derive(Debug, Deserialize)]
pub struct EnrollBeginRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct EnrollBeginResponse {
    pub user_id: String,
    pub creation_options: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct EnrollFinishRequest {
    pub user_id: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct EnrollFinishResponse {
    pub credential_id: String,
    pub registered_at_unix: u64,
    /// Issue #196: real `registerFirstMasterDevice` tx hash once the on-chain
    /// register shell-out succeeds. `None` on idempotent skip (already on chain),
    /// when no register script is configured, or when chain registration failed
    /// (see `chain` / `chain_error`). No longer a hard-coded stub.
    pub chain_tx_hash: Option<String>,
    /// "master-registered" once the master device is on chain with CAP_MINT (new
    /// tx OR idempotent-skip), else "none". Mirrors `GET /v1/onboarding/state`.
    pub chain: String,
    /// Populated only when the register shell-out FAILED — the passkey is still
    /// enrolled (the `credential_id` above is valid), but the chain write didn't
    /// land. The web UI surfaces this so the operator funds + retries instead of
    /// hitting a confusing cap-mint failure at plant time (issue #90 fail-loud).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
    /// #225 / E7: when `chain == "register-pending"`, the userOpHash the browser
    /// passkey must sign (a second Touch ID) and POST to `/v1/master/register/submit`
    /// to finish binding the master P256Account. `None` on skip/error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_userop_hash: Option<String>,
    /// #225 / E7: the deployed master P256Account address (operatorMasterWallet-to-be),
    /// shown in the ceremony UI. Present on both `register-pending` + skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_account: Option<String>,
}

// ── W1 onboarding: real email magic-link verify (broker-backed) ──

#[derive(Debug, Deserialize)]
pub struct EmailStartRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct EmailStartResponse {
    pub request_id: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailStatusQuery {
    pub request_id: String,
}

#[derive(Debug, Serialize)]
pub struct EmailStatusResponse {
    /// "pending" | "verified" | "failed:<reason>"
    pub status: String,
    /// Set when verified: the operator's identity omni (shown after login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omni_account: Option<String>,
}

/// The verified operator identity held in the daemon after the magic link is
/// clicked. Held server-side; never serialized to the browser.
#[derive(Clone, Debug)]
pub struct OnboardingSession {
    pub email: String,
    /// The EVM `actor_omni` after the managed-wallet attestation (SIWE→J1), or
    /// the identity omni if that step was skipped / unavailable.
    pub omni: String,
    /// The J1 (EVM-omni) session JWT — the daemon's authenticated bearer; held
    /// here, never handed to the browser. Read once cap-mint over the EVM session
    /// lands (next W-phase); held now so onboarding establishes the real session.
    #[allow(dead_code)]
    pub j1: String,
    /// The master's managed-wallet address (`0x` + 40 hex) — the persistence key
    /// for `~/.agentkeys/daemon-<wallet>/master-session.json` (issue #220). Empty
    /// for identity-only sessions (managed-wallet attestation skipped); those are
    /// not persisted, so the persistence path falls back to the omni.
    pub wallet: String,
}

#[derive(Debug, Serialize)]
pub struct OnboardingStateResponse {
    /// "verified" once the magic link is clicked + held; else "none".
    pub identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub omni: Option<String>,
    /// "enrolled" if a K11 passkey was registered this session, else "none".
    pub k11: String,
    /// Issue #196: "master-registered" once the master device is on chain with
    /// CAP_MINT (the K11-finish register shell-out landed or was idempotent-skip),
    /// else "none". This is the last onboarding gate before the memory plant
    /// button works end-to-end (real cap-mint resolves the on-chain device).
    pub chain: String,
    /// Issue #220: the durable-session signal that drives restart-resume in the
    /// web `lib/client`:
    ///   - "active"  → a still-valid J1 is held (rehydrated or fresh) — the
    ///     memory/config pages work with ZERO prompts;
    ///   - "expired" → master coords are persisted but the J1 lapsed — the web app
    ///     should prompt exactly ONE passkey re-auth (NOT a re-onboarding);
    ///   - "none"    → no persisted master session — full onboarding required.
    pub session: String,
    /// Issue #242: present when the daemon still knows WHO the master is (the
    /// logout-surviving coords) — the login screen offers "sign back in with
    /// Touch ID" against `/v1/auth/relogin/{start,finish}` instead of a full
    /// email re-onboarding. Display hints only; the broker re-verifies the
    /// passkey against the CHAIN before minting anything.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relogin: Option<ReloginInfo>,
}

/// The identity hint for the #242 passkey re-login button (who would be signed
/// back in). Sourced from the persisted master coords.
#[derive(Debug, Serialize)]
pub struct ReloginInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub omni: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    reason: &'static str,
}

fn err(
    status: StatusCode,
    error: impl Into<String>,
    reason: &'static str,
) -> (StatusCode, Json<ErrorBody>) {
    (
        status,
        Json(ErrorBody {
            error: error.into(),
            reason,
        }),
    )
}

/// Master-memory LIST route (daemon-local). The PLANT route — the contract the
/// frontend + harness both POST — is `MASTER_MEMORY_PLANT_ROUTE`, owned by
/// `agentkeys-protocol::web_api` (re-exported above, #275 tier-3): the React
/// frontend gets it from the `agentkeys-web-core` wasm export (one code path),
/// the harness demo is fixture-gated by `scripts/utils/check-web-api-drift.sh`, and
/// the fixture (`e2e/fixtures/web-api/master_memory_plant.json`) is pinned
/// to the shared const + `ApiMemoryEntry` shape by the unit test below.
pub const MASTER_MEMORY_ROUTE: &str = "/v1/master/memory";

/// Build the ui-bridge router with CORS open to the configured web-UI origin.
pub fn build_router(state: SharedUiBridgeState, allowed_origin: &str) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(
            allowed_origin
                .parse::<HeaderValue>()
                .unwrap_or(HeaderValue::from_static("http://localhost:3113")),
        )
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers(Any)
        .max_age(std::time::Duration::from_secs(600));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/k11/enroll/begin", post(enroll_begin))
        .route("/v1/k11/enroll/finish", post(enroll_finish))
        .route("/v1/master/register/submit", post(master_register_submit))
        // #435 — the fresh on-chain bound-probe onboarding consults BEFORE
        // minting a passkey (register-if-first / skip-if-bound):
        .route("/v1/master/register/state", get(master_register_state))
        .route("/v1/master/reset", post(master_reset))
        .route("/v1/auth/email/start", post(auth_email_start))
        .route("/v1/auth/email/status", get(auth_email_status))
        .route("/v1/onboarding/state", get(onboarding_state))
        .route("/v1/auth/logout", post(logout))
        // #242 — one-Touch-ID master re-login (no email round-trip).
        .route("/v1/auth/relogin/start", post(relogin_start))
        .route("/v1/auth/relogin/finish", post(relogin_finish))
        .route("/v1/actors", get(list_actors))
        .route("/v1/actors/:id", get(get_actor))
        .route("/v1/actors/:id/caps", get(list_caps))
        .route("/v1/actors/:id/scope", post(update_scope))
        .route("/v1/actors/:id/scope/grant", post(grant_service_scope))
        .route("/v1/actors/:id/payment-cap", post(update_payment_cap))
        .route("/v1/actors/:id/revoke", post(revoke_device))
        .route("/v1/actors/:id/caps/revoke", post(revoke_cap))
        .route("/v1/audit/recent", get(list_recent_audit))
        .route("/v1/audit/stream", get(audit_stream))
        .route("/v1/audit/:id/decode", get(decode_audit_event))
        .route("/v1/chain/info", get(chain_info))
        .route("/v1/chain/list", get(chain_list))
        .route("/v1/stack/list", get(stack_list))
        .route("/v1/anchor/status", get(anchor_status))
        .route("/v1/workers", get(list_workers))
        .route("/v1/workers/:id", get(get_worker))
        .route(MASTER_MEMORY_ROUTE, get(list_master_memory))
        .route("/v1/master/memory/entry", get(get_master_memory_entry))
        .route(MASTER_MEMORY_PLANT_ROUTE, post(plant_master_memory))
        // #339 P2 — absorption-inbox curate queue: the master lists delegate
        // proposals, then accepts (curate into canonical + GC) or rejects (GC).
        .route("/v1/master/inbox", get(list_master_inbox))
        .route("/v1/master/inbox/entry", post(get_master_inbox_entry))
        .route("/v1/master/inbox/accept", post(accept_master_inbox))
        .route("/v1/master/inbox/reject", post(reject_master_inbox))
        // #390 — persona editor (view/edit/rollback) + the agent restart /
        // live-context-view legs (master-hub-topology.md §16).
        .route("/v1/master/persona", get(get_master_persona))
        .route("/v1/master/persona", post(edit_master_persona))
        .route("/v1/master/persona/rollback", post(rollback_master_persona))
        .route("/v1/master/persona/delete", post(delete_master_persona))
        .route("/v1/master/agent/restart", post(restart_master_agent))
        .route("/v1/master/agent/context", get(get_master_agent_context))
        // #404 — the master's channel registry (id-anchored channel definitions;
        // the device pages SELECT from it — channels are never created silently):
        .route("/v1/channels", get(list_channels))
        .route("/v1/channels", post(create_channel))
        .route("/v1/channels/:id", post(update_channel))
        .route("/v1/channels/:id/delete", post(delete_channel))
        .route("/v1/master/config/presets", get(list_config_presets))
        // #428 — the spawn preset catalog (broker-served, static; proxied so
        // the web app keeps its single daemon origin):
        .route("/v1/presets", get(presets_catalog_proxy))
        .route("/v1/presets/:id", get(preset_bundle_proxy))
        .route("/v1/master/config/init", post(init_config_default))
        .route("/v1/master/classify/tag", post(classify_tag))
        .route("/v1/master/classify/propose", post(classify_propose))
        .route("/v1/master/credentials", get(list_master_credentials))
        .route(
            "/v1/master/credentials/store",
            post(store_master_credential),
        )
        // Agent pairing — the web-app half of the §10.2 agent-initiated ceremony
        // (issue #214). The master pulls the broker's pending agent bindings
        // (agents it claimed, awaiting on-chain register) for the pairing screen.
        .route("/v1/agent/pairing/pending", get(list_pairing_requests))
        .route("/v1/agent/pairing/claim", post(claim_pairing))
        .route("/v1/agent/pairing/decline", post(decline_pairing))
        .route("/v1/agent/pairing/ack", post(ack_pairing))
        .route("/v1/agent/pairing/register", post(register_pairing))
        // #225 E7 — the Touch-ID-gated accept (browser K11-signs the userOpHash):
        .route("/v1/accept/build", post(accept_build_proxy))
        .route("/v1/accept/submit", post(accept_submit_proxy))
        .route("/v1/scope/build", post(scope_build_proxy))
        .route("/v1/scope/submit", post(scope_submit_proxy))
        // #427 — the delegate spawn/archive ceremonies (ONE Touch ID each; the
        // broker enforces the on-chain agent-slot allowance; the daemon writes
        // the #424 binding-manifest row on confirm):
        .route("/v1/agent/spawn/build", post(spawn_build_proxy))
        .route("/v1/agent/spawn/submit", post(spawn_submit_proxy))
        .route("/v1/agent/archive/build", post(archive_build_proxy))
        .route("/v1/agent/archive/submit", post(archive_submit_proxy))
        // #429 — O2 inheritance bookkeeping (kept namespaces of archived
        // delegates, at most one live inheritor by construction):
        .route(
            "/v1/agent/inheritable-namespaces",
            get(list_inheritable_namespaces),
        )
        // #430 — the operator chat surface over the delegate's opchat feed
        // (D8 operator-owned; D13: operator session only):
        .route("/v1/master/agent/chat/send", post(master_chat_send))
        .route("/v1/master/agent/chat/poll", post(master_chat_poll))
        // #418 — the WeChat gateway admin proxy (parent-control drives the
        // gateway's admin surface through the daemon; the admin bearer is
        // injected server-side, never in the browser):
        .route("/v1/master/gateway/status", get(gateway_status_proxy))
        .route("/v1/master/gateway/monitor", get(gateway_monitor_proxy))
        .route("/v1/master/gateway/history", get(gateway_history_proxy))
        .route("/v1/master/gateway/activity", get(gateway_activity_proxy))
        .route(
            "/v1/master/gateway/login/start",
            post(gateway_login_start_proxy),
        )
        .route(
            "/v1/master/gateway/login/status",
            get(gateway_login_status_proxy),
        )
        .route(
            "/v1/master/gateway/login/verify",
            post(gateway_login_verify_proxy),
        )
        .route(
            "/v1/master/gateway/login/disconnect",
            post(gateway_login_disconnect_proxy),
        )
        .route(
            "/v1/master/gateway/bind/invite",
            post(gateway_bind_invite_proxy),
        )
        .route(
            "/v1/master/gateway/bind/pending",
            get(gateway_bind_pending_proxy),
        )
        .route(
            "/v1/master/gateway/bind/approve",
            post(gateway_bind_approve_proxy),
        )
        .route(
            "/v1/master/gateway/bind/reject",
            post(gateway_bind_reject_proxy),
        )
        .route("/v1/master/gateway/contacts", get(gateway_contacts_proxy))
        .route(
            "/v1/master/gateway/contacts/update",
            post(gateway_contacts_update_proxy),
        )
        .route(
            "/v1/master/gateway/contacts/revoke",
            post(gateway_contacts_revoke_proxy),
        )
        .route("/v1/revoke/build", post(revoke_build_proxy))
        .route("/v1/revoke/submit", post(revoke_submit_proxy))
        .route("/v1/dev/seed", post(dev_seed))
        .route("/v1/dev/event", post(dev_emit_event))
        .layer(cors)
        .with_state(state)
}

/// Build the bridge state. `rp_id` is the WebAuthn relying-party id —
/// always "localhost" for dev, "agentkeys.io" (or operator domain) in
/// production. `rp_origin` is the browser's window.location.origin.
// Runtime-config constructor: the params ARE the daemon's config surface (RP +
// broker/signer + chain + W3 memory). Bundling into a config struct is deferred
// (W2 adds more chain config here); clippy's documented escape for constructors.
/// Derive a co-located worker's public URL from the broker URL, mirroring the
/// operator scripts' `derive_companion` (setup-broker-host.sh) + the env files'
/// `<worker><suffix>.<zone>` convention — so the daemon reasons the gateway (and
/// any co-located worker) from the broker it already points at, instead of a
/// hardcoded per-stack env var. Returns `None` when the broker host isn't a
/// recognized `broker*.<zone>` public host (e.g. a bare IP / localhost for a
/// dev broker); the worker is then simply unreachable and the caller treats it
/// as not-configured.
///
/// Stack → suffix (from the broker host's first DNS label):
/// - `broker.<zone>`        → `""`        (prod)
/// - `test-broker.<zone>`   → `"-test"`   (#265 slot 1 — grandfathered `test-` prefix)
/// - `broker-test-2.<zone>` → `"-test-2"` (test-fleet slot N)
/// - `broker-base.<zone>`   → `"-base"`   (#282 Base stack)
fn derive_worker_url(broker_url: &str, worker: &str) -> Option<String> {
    let host = broker_url
        .rsplit("://")
        .next()
        .unwrap_or(broker_url)
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    let (first, zone) = host.split_once('.')?;
    if zone.is_empty() {
        return None;
    }
    let suffix = match first {
        "broker" => String::new(),
        "test-broker" => "-test".to_string(),
        other => match other.strip_prefix("broker-") {
            Some(rest) if !rest.is_empty() => format!("-{rest}"),
            _ => return None,
        },
    };
    Some(format!("https://{worker}{suffix}.{zone}"))
}

#[allow(clippy::too_many_arguments)]
pub fn build_state(
    rp_id: &str,
    rp_origin: &str,
    rp_name: &str,
    broker_url: Option<String>,
    signer_url: Option<String>,
    chain_id: u64,
    memory_url: Option<String>,
    memory_role_arn: Option<String>,
    config_url: Option<String>,
    config_role_arn: Option<String>,
    classify_url: Option<String>,
    sandbox_bridge_url: Option<String>,
    sandbox_bridge_token: Option<String>,
    audit_worker_url: Option<String>,
    region: String,
    master_device_key_hash: Option<String>,
    register_master_script: Option<String>,
    master_session_store: Option<MasterSessionStore>,
) -> anyhow::Result<SharedUiBridgeState> {
    let origin = Url::parse(rp_origin)?;
    let builder = WebauthnBuilder::new(rp_id, &origin)?.rp_name(rp_name);
    let webauthn = builder.build()?;
    let (audit_tx, _audit_rx) = broadcast::channel::<ApiAuditEvent>(256);
    // Resolve the chain profile (deployed contract registry + explorer) from
    // $AGENTKEYS_CHAIN, defaulting to heima mainnet. Drives /v1/chain/info +
    // /v1/audit/:id/decode (#153). Never hard-fails: an unknown chain name
    // falls back to the embedded heima profile.
    let mut chain_profile = match agentkeys_core::chain_profile::ChainProfile::resolve(
        None,
        std::env::var("AGENTKEYS_CHAIN").ok().as_deref(),
        std::env::var("AGENTKEYS_CHAIN_PROFILE_FILE")
            .ok()
            .as_deref(),
    ) {
        Ok((p, _)) => p,
        Err(e) => {
            // codex review #153: don't silently serve heima addresses when the
            // operator set a bad $AGENTKEYS_CHAIN / profile file — warn loudly so
            // /v1/chain/info isn't trusted as the wrong chain.
            tracing::warn!(
                error = %e,
                "ui-bridge: chain profile resolution failed; falling back to heima — \
                 /v1/chain/info will show heima addresses regardless of the requested chain"
            );
            agentkeys_core::chain_profile::ChainProfile::load_builtin("heima")?
        }
    };
    // The daemon was the ONLY component sourcing its RPC from the compiled chain profile;
    // the broker (accept.rs/cap.rs), every worker (state.rs) and the bundler all read
    // AGENTKEYS_CHAIN_RPC_HTTP from their env. Read the same var here (dev.sh sources it
    // from operator-workstation.<chain>.env, like setup-broker-host.sh does for the broker)
    // so the daemon's chain reads AND /v1/chain/info (the top-right badge) match the rest
    // of the system instead of diverging on the profile default.
    if let Some(rpc) = chain_rpc_from_env(&chain_profile.name, |k| std::env::var(k).ok()) {
        tracing::info!(
            chain = %chain_profile.name, rpc = %rpc,
            "ui-bridge: chain RPC from AGENTKEYS_CHAIN_RPC_HTTP[_<CHAIN>] env (matches broker/workers/bundler)"
        );
        chain_profile.rpc.http = rpc;
    }
    // #418 — the WeChat gateway admin proxy coordinates (env-sourced like
    // AGENTKEYS_STACKS_JSON above). The URL is DERIVED from the broker URL
    // (`weixin<stack-suffix>.<zone>`, mirroring the operator scripts'
    // `derive_companion`) so the operator never hardcodes a per-stack worker URL
    // — an explicit `AGENTKEYS_WORKER_WEIXIN_URL` still overrides. The admin
    // token is a SECRET the operator retrieves from the broker's
    // weixin-secrets.env; the daemon injects it server-side (never the browser).
    let weixin_gateway_url = std::env::var("AGENTKEYS_WORKER_WEIXIN_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            broker_url
                .as_deref()
                .and_then(|b| derive_worker_url(b, "weixin"))
        });
    let weixin_admin_token = std::env::var("AGENTKEYS_WEIXIN_ADMIN_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(Arc::new(UiBridgeState {
        webauthn,
        enroll: RwLock::new(EnrollState::default()),
        fleet_gen: std::sync::atomic::AtomicU64::new(1),
        fleet_synced_gen: std::sync::atomic::AtomicU64::new(0),
        fleet_sync_lock: tokio::sync::Mutex::new(()),
        actors: RwLock::new(HashMap::new()),
        caps: RwLock::new(HashMap::new()),
        audit: RwLock::new(VecDeque::with_capacity(AUDIT_BUFFER_CAP)),
        audit_tx,
        workers: RwLock::new(HashMap::new()),
        anchor: RwLock::new(ApiAnchorStatus::default()),
        master_memory: RwLock::new(HashMap::new()),
        plant_lock: tokio::sync::Mutex::new(()),
        authored_taxonomy: RwLock::new(None),
        accept_grants_by_request: RwLock::new(HashMap::new()),
        ceremony_context_by_dkh: RwLock::new(HashMap::new()),
        channel_registry: RwLock::new(None),
        binding_manifest: RwLock::new(None),
        scope_services_by_op_hash: RwLock::new(HashMap::new()),
        gateway_registry_synced: std::sync::atomic::AtomicBool::new(false),
        stacks: parse_stacks_json(std::env::var("AGENTKEYS_STACKS_JSON").ok().as_deref()),
        broker_url,
        allowed_origin: rp_origin.to_string(),
        pending_email: RwLock::new(HashMap::new()),
        onboarding_session: RwLock::new(None),
        signer_url,
        chain_id,
        memory_url,
        memory_role_arn,
        config_url,
        config_role_arn,
        classify_url,
        sandbox_bridge_url,
        sandbox_bridge_token,
        audit_worker_url,
        weixin_gateway_url,
        weixin_admin_token,
        region,
        master_device_key_hash,
        registered_master: RwLock::new(None),
        register_master_script,
        chain_profile,
        master_session_store,
        master_session: RwLock::new(None),
        pending_register: RwLock::new(None),
    }))
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true, "surface": "ui-bridge" }))
}

/// W1: request a magic-link email. Proxies the broker's `email/request` so the
/// browser never holds broker URLs; returns the `request_id` the browser polls.
/// Server-side origin gate for the onboarding email endpoints (defense-in-depth
/// on top of CORS): a present `Origin` that doesn't match the configured app
/// origin is rejected, so a cross-origin page can't trigger magic-link emails.
/// A missing Origin (non-browser / CLI) is allowed.
fn reject_cross_origin(
    state: &SharedUiBridgeState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if origin != state.allowed_origin {
            return Err(err(
                StatusCode::FORBIDDEN,
                format!("cross-origin onboarding request from {origin} rejected"),
                "bad-origin",
            ));
        }
    }
    Ok(())
}

async fn auth_email_start(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
    Json(req): Json<EmailStartRequest>,
) -> Result<Json<EmailStartResponse>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let broker = state.broker_url.as_deref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "email onboarding disabled (daemon started without --broker-url)",
            "broker-not-configured",
        )
    })?;
    if req.email.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "email required",
            "missing-email",
        ));
    }
    let request_id = init_flow::email_request(broker, req.email.trim())
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("broker email/request failed: {e}"),
                "broker-email-failed",
            )
        })?;
    state
        .pending_email
        .write()
        .await
        .insert(request_id.clone(), req.email.trim().to_string());
    Ok(Json(EmailStartResponse { request_id }))
}

/// W1: poll the magic-link status (the browser calls this on a timer until the
/// status is no longer `pending` — i.e. the operator clicked the link).
async fn auth_email_status(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<EmailStatusQuery>,
) -> Result<Json<EmailStatusResponse>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let broker = state.broker_url.as_deref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "email onboarding disabled (daemon started without --broker-url)",
            "broker-not-configured",
        )
    })?;
    let status = init_flow::auth_status_once(broker, "email", &q.request_id)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("broker email/status failed: {e}"),
                "broker-status-failed",
            )
        })?;
    let resp = match status {
        init_flow::AuthStatus::Pending => EmailStatusResponse {
            status: "pending".into(),
            omni_account: None,
        },
        init_flow::AuthStatus::Verified {
            session_jwt,
            identity_omni,
        } => {
            let email = state
                .pending_email
                .read()
                .await
                .get(&q.request_id)
                .cloned()
                .unwrap_or_default();
            // Managed-wallet attestation (SIWE→J1): the signer derives + attests
            // the managed wallet for this email identity (no user wallet) and the
            // broker mints J1. On success we hold the EVM `actor_omni` + J1; if the
            // signer is unconfigured/unreachable we fall back to the identity-only
            // session so onboarding still completes (the EVM session can retry).
            let held = match state.signer_url.as_deref() {
                Some(signer) => match init_flow::finish_email_session(
                    broker,
                    signer,
                    &session_jwt,
                    &identity_omni,
                    state.chain_id,
                    &email,
                )
                .await
                {
                    Ok(init) => OnboardingSession {
                        email,
                        omni: init.evm_omni,
                        j1: init.session.token.clone(),
                        wallet: init.session.wallet.0.clone(),
                    },
                    Err(e) => {
                        tracing::warn!(
                            "ui-bridge: SIWE->J1 attestation failed, holding identity-only: {e}"
                        );
                        OnboardingSession {
                            email,
                            omni: identity_omni,
                            j1: String::new(),
                            wallet: String::new(),
                        }
                    }
                },
                None => OnboardingSession {
                    email,
                    omni: identity_omni,
                    j1: String::new(),
                    wallet: String::new(),
                },
            };
            let omni = held.omni.clone();
            *state.onboarding_session.write().await = Some(held);
            // Issue #220: persist the master coords so a daemon restart with a
            // still-valid J1 rehydrates with zero prompts (no re-onboarding).
            // No-op for identity-only sessions (empty J1) or when persistence is
            // disabled. Done before returning so the file exists immediately.
            persist_master_session(&state).await;
            EmailStatusResponse {
                status: "verified".into(),
                omni_account: Some(omni),
            }
        }
        init_flow::AuthStatus::Failed(reason) => EmailStatusResponse {
            status: format!("failed:{reason}"),
            omni_account: None,
        },
    };
    Ok(Json(resp))
}

/// W1: aggregate onboarding state — the real "are we logged in" signal that
/// replaces the browser's `ak_onboarded` localStorage flag. Identity is held in
/// the daemon (never the browser); `k11` reflects the in-memory enroll store.
async fn onboarding_state(
    State(state): State<SharedUiBridgeState>,
) -> Json<OnboardingStateResponse> {
    let live_session = state.onboarding_session.read().await.clone();
    let k11 = if state.enroll.read().await.registered.is_empty() {
        "none"
    } else {
        "enrolled"
    };
    // Issue #242 cross-email guard: "master-registered" must mean registered for
    // THE LIVE SESSION's omni. A new-email login while the previous binding is
    // still held used to mis-report the OLD master as the new identity's (the
    // ceremony then reused the wrong passkey pointer). No live session ⇒ report
    // the held binding as-is (pre-login surfaces key off `relogin`, not `chain`).
    let chain = match (
        state.registered_master.read().await.as_ref(),
        live_session.as_ref(),
    ) {
        (Some(rm), Some(s)) if !s.omni.is_empty() => {
            let norm = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
            if norm(&rm.operator_omni) == norm(&s.omni) {
                "master-registered"
            } else {
                "none"
            }
        }
        (Some(_), _) => "master-registered",
        (None, _) => "none",
    };
    // Issue #220 durable-session signal: a live, non-empty J1 ⇒ "active"; else
    // persisted-but-lapsed coords ⇒ "expired" (drives one passkey re-auth); else
    // "none" (full onboarding). The web `lib/client` reads this to decide whether
    // a restart needs zero / one / a full ceremony.
    let session = if live_session
        .as_ref()
        .map(|s| !s.j1.is_empty())
        .unwrap_or(false)
    {
        "active"
    } else if state.master_session.read().await.is_some() {
        "expired"
    } else {
        "none"
    };
    // Issue #242: the logout-surviving identity hint for the re-login button.
    // Coords present (valid OR expired J1) ⇒ the daemon knows who the master is;
    // the broker re-verifies the passkey against the chain before minting.
    let relogin = state
        .master_session
        .read()
        .await
        .as_ref()
        .filter(|r| !r.operator_omni.is_empty())
        .map(|r| ReloginInfo {
            email: (!r.email.is_empty()).then(|| r.email.clone()),
            omni: r.operator_omni.clone(),
        });
    let (identity, email, omni) = match live_session {
        Some(s) => ("verified".to_string(), Some(s.email), Some(s.omni)),
        None => ("none".to_string(), None, None),
    };
    Json(OnboardingStateResponse {
        identity,
        email,
        omni,
        k11: k11.to_string(),
        chain: chain.to_string(),
        session: session.to_string(),
        relogin,
    })
}

/// W1: drop the live session (logout) — the J1 + the in-memory identity go
/// away, so nothing can act as the master until a re-auth. Since #242 the
/// logout is a *sign-out*, not a forget-account: the persisted master coords
/// (email/omni/wallet — public identity hints, never key material) are KEPT,
/// downgraded to an EXPIRED record (`j1: ""`), so:
///   - a restart can NEVER silently rehydrate a logged-out session (the #220
///     guarantee — `j1_valid_at` is false for an empty J1);
///   - the login screen can offer the one-Touch-ID passkey re-login
///     (`/v1/auth/relogin/*`) instead of forcing a full email re-onboarding.
///
/// The REAL forget-account is `POST /v1/master/reset` (clears coords + the
/// on-chain binding). Re-testability per arch.md §6 is unchanged: the same
/// email re-verifies to the same `actor_omni` either way.
async fn logout(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    *state.onboarding_session.write().await = None;
    state.pending_email.write().await.clear();
    let downgraded = state.master_session.read().await.clone().map(|mut r| {
        r.j1 = String::new();
        r.j1_exp_unix = 0;
        r
    });
    if let (Some(store), Some(record)) = (state.master_session_store.as_ref(), downgraded.as_ref())
    {
        if let Err(e) = store.save(record) {
            tracing::warn!("ui-bridge #242: failed to persist logged-out master coords: {e}");
        }
    }
    *state.master_session.write().await = downgraded;
    Json(serde_json::json!({ "ok": true }))
}

/// `POST /v1/auth/relogin/start` (#242) — begin the one-Touch-ID master
/// re-login. Uses the logout-surviving coords (`master_session`) to ask the
/// broker for a chain-bound challenge; the browser signs it with the BOUND
/// passkey (`getAssertionOverHash(challenge, [ak_master_cred_id])`) and posts
/// the assertion to `/v1/auth/relogin/finish`. The daemon supplies only the
/// CLAIM (the omni); the broker verifies the assertion against the chain.
async fn relogin_start(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
) -> Result<Json<ReloginStartResponse>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let Some(broker) = state.broker_url.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "passkey re-login disabled (daemon started without --broker-url)",
            "broker-not-configured",
        ));
    };
    let coords = state.master_session.read().await.clone();
    let Some(coords) = coords.filter(|c| !c.operator_omni.is_empty()) else {
        return Err(err(
            StatusCode::CONFLICT,
            "no master identity held — onboard via email first",
            "no-master-identity",
        ));
    };
    let start = init_flow::passkey_reauth_start(&broker, &coords.operator_omni)
        .await
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("broker passkey/start failed: {e}"),
                "broker-passkey-start-failed",
            )
        })?;
    Ok(Json(ReloginStartResponse {
        challenge: start.challenge,
        account: start.account,
        email: coords.email,
        omni: coords.operator_omni,
    }))
}

#[derive(Debug, Serialize)]
struct ReloginStartResponse {
    /// `0x` + 64 hex — the browser signs THIS via `getAssertionOverHash`.
    challenge: String,
    /// The on-chain master P256Account the assertion must satisfy (display).
    account: String,
    email: String,
    omni: String,
}

#[derive(Debug, Deserialize)]
struct ReloginFinishRequest {
    challenge: String,
    /// The browser WebAuthn assertion, passed to the broker verbatim
    /// (`{ authenticator_data, client_data_json, signature, credential_id }`).
    assertion: serde_json::Value,
}

/// `POST /v1/auth/relogin/finish` (#242) — submit the assertion; on the
/// broker's chain-verified OK, restore the full master session: the fresh J1
/// becomes the live `onboarding_session`, `registered_master` is repopulated
/// from the coords (the binding never left the chain), and the #220 store is
/// re-persisted so restart-resume works again. ONE Touch ID, zero emails.
async fn relogin_finish(
    State(state): State<SharedUiBridgeState>,
    headers: HeaderMap,
    Json(req): Json<ReloginFinishRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    reject_cross_origin(&state, &headers)?;
    let Some(broker) = state.broker_url.clone() else {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "passkey re-login disabled (daemon started without --broker-url)",
            "broker-not-configured",
        ));
    };
    let coords = state.master_session.read().await.clone();
    let Some(coords) = coords.filter(|c| !c.operator_omni.is_empty()) else {
        return Err(err(
            StatusCode::CONFLICT,
            "no master identity held — onboard via email first",
            "no-master-identity",
        ));
    };
    let verified = init_flow::passkey_reauth_verify(&broker, &req.challenge, req.assertion)
        .await
        .map_err(|e| match e {
            init_flow::InitFlowError::BrokerRejected {
                status: 401, body, ..
            } => err(
                StatusCode::UNAUTHORIZED,
                format!("passkey re-auth rejected: {body}"),
                "assertion-rejected",
            ),
            other => err(
                StatusCode::BAD_GATEWAY,
                format!("broker passkey/verify failed: {other}"),
                "broker-passkey-verify-failed",
            ),
        })?;
    // The broker minted for the CHAIN-verified omni; it must be the identity we
    // hold, or the session would silently switch masters.
    let norm = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
    if norm(&verified.omni_account) != norm(&coords.operator_omni) {
        return Err(err(
            StatusCode::CONFLICT,
            format!(
                "broker verified omni {} but the held master identity is {}",
                verified.omni_account, coords.operator_omni
            ),
            "omni-mismatch",
        ));
    }
    *state.onboarding_session.write().await = Some(OnboardingSession {
        email: coords.email.clone(),
        omni: coords.operator_omni.clone(),
        j1: verified.session_jwt,
        wallet: coords.wallet.clone(),
    });
    // The on-chain binding never left — repopulate the local record so cap-mint
    // + onboarding-state see the registered master without a re-probe. The
    // account address is read from chain by list_actors when absent.
    mark_master_registered(
        &state,
        RegisteredMaster {
            device_key_hash: coords.device_key_hash.clone(),
            operator_omni: coords.operator_omni.clone(),
            tx_hash: None,
            account: None,
        },
    )
    .await;
    persist_master_session(&state).await;
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        omni = %coords.operator_omni,
        "issue #242: master re-login complete — session restored with one passkey prompt"
    );
    Ok(Json(serde_json::json!({
        "ok": true,
        "omni": coords.operator_omni,
        "email": coords.email,
    })))
}

/// `POST /v1/master/reset` (#225 E7, fleet teardown #243) — fully unbind the master
/// so the operator can re-onboard with a FRESH passkey (used when the bound master
/// passkey was deleted in the OS password manager, or got out of sync via a
/// re-onboard). Three parts — the fleet teardown FIRST (it needs the still-live J1
/// + intact actor map), then the unbind, then the local clear:
///
/// 0. **FLEET (#243, #260)** — decline every pending pairing row at the broker,
///    revoke every paired agent device on chain, clear the actors/caps maps + the
///    K11 enroll store. Who revokes depends on the master model (#260): an
///    account-master's agents can ONLY be revoked by the master P256Account, so
///    the UI runs ONE Touch-ID `executeBatch([revokeAgentDevice × N])` UserOp
///    BEFORE calling this endpoint and this step verifies the chain reads
///    `revoked` per agent; a legacy EOA-master's agents are revoked here via
///    `heima-device-revoke.sh` (agent-tier, no K11). Failures land in the
///    `fleet.failures` response field. ONE case aborts the whole reset: an
///    account master with agents still bound on chain — unbinding first would
///    permanently strand those bindings, so the response comes back
///    `ok: false, needs_fleet_revoke: true` and nothing is mutated. Without
///    the teardown, a reset left the old agents silently attached to the omni.
///
/// 1. **ON-CHAIN** — shell out to `heima-reset-master.sh`, which calls the registry's
///    owner-gated `resetMaster(operatorOmni)` (the deployer key) to clear
///    `operatorMasterWallet[omni]`. This is the part that actually lets a fresh passkey
///    re-bind: `registerFirstMasterDevice` is first-master-ONLY, so WITHOUT this the
///    immutable binding keeps the new passkey from binding and accept keeps failing
///    SIG_VALIDATION. Best-effort + surfaced: a failure (registry pre-VERSION-0.3 / no
///    `resetMaster`, missing deployer key) is reported in the response, not swallowed.
/// 2. **LOCAL** — clear `registered_master` + any in-flight `pending_register` + the
///    persisted master-session coords, so `GET /v1/onboarding/state` drops back to
///    `chain: "none"` and the onboarding ceremony enrolls fresh (it normally SKIPS when
///    a master is bound). Always runs, even if (1) fails, so the UI isn't stuck.
///
/// KEEPS the email/J1 session (re-onboard needs no re-verify). CANNOT touch the **OS
/// passkey** (WebAuthn forbids a site from deleting a credential) — the UI must tell the
/// operator to delete the master passkey in System Settings → Passwords.
async fn master_reset(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    // Capture the operator omni BEFORE clearing local state (the on-chain reset needs
    // it). Prefer the registered-master omni (what's actually bound on chain), then the
    // persisted session, then the live onboarding session. Each read guard is dropped at
    // its statement end — none held across an await.
    let from_registered = state
        .registered_master
        .read()
        .await
        .as_ref()
        .map(|rm| rm.operator_omni.clone());
    let from_session = state
        .master_session
        .read()
        .await
        .as_ref()
        .map(|ms| ms.operator_omni.clone());
    let from_onboarding = state
        .onboarding_session
        .read()
        .await
        .as_ref()
        .map(|s| s.omni.clone());
    let operator_omni = [from_registered, from_session, from_onboarding]
        .into_iter()
        .flatten()
        .find(|o| !o.is_empty())
        .map(|o| agentkeys_backend_client::normalize_omni_0x(&o));

    // (0) FLEET teardown (#243, #260) — BEFORE the master unbind so every
    // sub-step still has its authority: the pending-pairing declines ride the
    // (kept) J1 at the broker; EOA-master agent revokes are agent-tier via the
    // deployer script (no K11 — the flow must also work when the OS passkey is
    // already deleted, the very case reset exists for); account-master agent
    // revokes happened in the browser's pre-reset Touch-ID fleet UserOp and are
    // verified from chain here. Failures are collected + surfaced in the `fleet`
    // response field. One case aborts (ok:false, nothing mutated): an account
    // master whose agents are still bound — see the #260 hard stop below.
    let mut fleet_failures: Vec<String> = Vec::new();

    // (0a) Decline every pending pairing row at the broker, so claimed-but-
    // unapproved agents stop reappearing on the pairing page after re-onboard.
    let mut pending_declined = 0usize;
    {
        let j1 = state
            .onboarding_session
            .read()
            .await
            .as_ref()
            .map(|s| s.j1.clone())
            .filter(|j| !j.is_empty());
        match (state.broker_url.clone(), j1) {
            (Some(broker), Some(j1)) => {
                match agentkeys_cli::agent_admin::agent_pending_value(&broker, &j1).await {
                    Ok(v) => {
                        let ids: Vec<String> = v
                            .get("pending")
                            .and_then(|p| p.as_array())
                            .map(|rows| {
                                rows.iter()
                                    .filter_map(|b| {
                                        b.get("request_id")
                                            .and_then(serde_json::Value::as_str)
                                            .map(str::to_string)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        for id in ids {
                            let resp = forward_to_broker(
                                &broker,
                                "/v1/agent/pairing/decline",
                                &j1,
                                &serde_json::json!({ "request_id": id }),
                            )
                            .await;
                            if resp.status().is_success() {
                                pending_declined += 1;
                            } else {
                                fleet_failures
                                    .push(format!("decline {id}: HTTP {}", resp.status()));
                            }
                        }
                    }
                    Err(e) => fleet_failures.push(format!("pending-bindings list: {e:#}")),
                }
            }
            (None, _) => {} // no broker configured (dev) — nothing to decline
            (_, None) => fleet_failures.push(
                "pending pairings not declined: no live master session (J1) — decline them \
                 from the pairing page after re-onboarding"
                    .into(),
            ),
        }
    }

    // (0b) Revoke every paired agent device ON CHAIN and append an audit row per
    // revocation. A binding is not gone until the chain says so; skipping this is
    // exactly the silently-attached-fleet trap #243 closes. The fleet is
    // reconciled FROM CHAIN first (#233): post-restart the in-memory map is empty
    // while agents are still bound — without this, a restart-then-reset would
    // revoke nothing while reporting a clean teardown.
    //
    // WHO revokes depends on the master model (#260): an account-master's agents
    // can ONLY be revoked by the master P256Account itself — the browser runs ONE
    // Touch-ID `executeBatch([revokeAgentDevice × N])` UserOp BEFORE calling this
    // endpoint, and this step verifies the chain now reads `revoked` per agent.
    // A legacy EOA-master's agents are revoked here via the deployer script
    // (`heima-device-revoke.sh`, idempotent, agent-tier).
    if let Err(e) = reconcile_actors_from_chain(&state).await {
        fleet_failures.push(format!(
            "chain fleet reconstruction failed ({e}) — revoking only the locally-known agents; \
             re-run reset once the RPC is reachable"
        ));
    }
    let agents: Vec<(String, String, Option<String>)> = state
        .actors
        .read()
        .await
        .values()
        .filter(|a| a.role == "agent")
        .map(|a| (a.id.clone(), a.label.clone(), a.device_key_hash.clone()))
        .collect();
    let mut agents_revoked: Vec<serde_json::Value> = Vec::new();
    if !agents.is_empty() {
        // #260 ground truth: ONE chain-fleet read drives (a) the already-revoked
        // skip — the pre-reset Touch-ID fleet revoke normally lands first, so
        // agents arrive here pre-revoked — and (b) the account-master guard.
        // Best-effort: an unreachable RPC degrades to the legacy script-per-agent
        // behavior (reconcile already surfaced the failure above).
        let registry = registry_address(&state);
        let rpc = state.chain_profile.rpc.http.clone();
        let norm_hash = |h: &str| h.trim().trim_start_matches("0x").to_lowercase();
        let revoked_on_chain: std::collections::HashSet<String> = match (&registry, &operator_omni)
        {
            (Some(reg), Some(omni)) => match fetch_chain_fleet(&rpc, reg, omni).await {
                Ok(fleet) => fleet
                    .iter()
                    .filter(|d| d.revoked)
                    .map(|d| norm_hash(&d.device_key_hash))
                    .collect(),
                Err(e) => {
                    tracing::warn!(
                        target: "agentkeys.daemon.ui_bridge",
                        "reset teardown: chain fleet read failed ({e}) — falling back to the \
                         script path for every agent"
                    );
                    Default::default()
                }
            },
            _ => Default::default(),
        };
        // The master model decides who CAN revoke a still-active agent: a passkey
        // P256Account master (account has code) means NO EOA — incl. the deployer
        // script — can sign revokeAgentDevice (#260). Unknown (RPC down / no
        // master on chain) fails open to today's script behavior.
        let master_is_account = match (&registry, &operator_omni) {
            (Some(reg), Some(omni)) => match fetch_operator_master_wallet(&rpc, reg, omni).await {
                Some(addr) => daemon_eth_address_has_code(&rpc, &addr)
                    .await
                    .unwrap_or(false),
                None => false,
            },
            _ => false,
        };

        let mut needs_script: Vec<&(String, String, Option<String>)> = Vec::new();
        let mut agents_still_bound: Vec<serde_json::Value> = Vec::new();
        for agent in &agents {
            let (id, label, device_key_hash) = agent;
            let already_revoked = device_key_hash
                .as_deref()
                .map(|h| revoked_on_chain.contains(&norm_hash(h)))
                .unwrap_or(false);
            if already_revoked {
                push_audit(
                    &state,
                    ApiAuditEvent {
                        id: format!("e-reset-revoke-{}-{id}", now_unix()),
                        ts: now_ts_hms(),
                        actor_id: "master".into(),
                        actor: "master".into(),
                        kind: "device.revoked".into(),
                        detail: format!(
                            "{id} · master-reset fleet teardown · on-chain revokeAgentDevice \
                             (already revoked — Touch-ID fleet revoke landed before the reset)"
                        ),
                        chip: "revoke".into(),
                        sev: "bad".into(),
                        tx_hash: None,
                        audit_envelope_hashes: None,
                    },
                )
                .await;
                agents_revoked.push(serde_json::json!({
                    "id": id, "label": label, "tx_hash": null, "already_revoked": true,
                }));
                continue;
            }
            if master_is_account {
                // The EOA script is guaranteed to revert NotAuthorized here —
                // don't even attempt it; the abort below routes the operator to
                // the Touch-ID fleet revoke instead.
                agents_still_bound.push(serde_json::json!({
                    "id": id, "label": label, "device_key_hash": device_key_hash,
                }));
                fleet_failures.push(format!(
                    "revoke {label}: still bound on chain and the master is a passkey \
                     P256Account — no EOA script can sign revokeAgentDevice; approve the \
                     Touch-ID fleet revoke first"
                ));
                continue;
            }
            needs_script.push(agent);
        }

        // #260 HARD STOP: unbinding the master clears operatorMasterWallet[omni],
        // after which NOBODY can revoke these agents (until a new master re-binds
        // under the same omni). Abort BEFORE the unbind; the UI runs the
        // one-Touch-ID fleet revoke (/v1/revoke/{build,submit}) and re-POSTs the
        // reset, which then sees the agents revoked and proceeds.
        if !agents_still_bound.is_empty() {
            let n = agents_still_bound.len();
            return Json(serde_json::json!({
                "ok": false,
                "needs_fleet_revoke": true,
                "onchain": {
                    "status": "aborted",
                    "reason": "account-master-agents-still-bound",
                },
                "fleet": {
                    "pending_declined": pending_declined,
                    "agents_revoked": agents_revoked,
                    "actors_cleared": 0,
                    "k11_enroll_cleared": false,
                    "failures": fleet_failures,
                    "agents_still_bound": agents_still_bound,
                },
                "note": format!(
                    "reset aborted: {n} agent(s) are still bound on chain and only the master \
                     P256Account can revoke them. Approve the Touch-ID fleet revoke (one \
                     approval revokes all of them), then reset again. Nothing was unbound or \
                     cleared."
                ),
            }));
        }

        if !needs_script.is_empty() {
            let revoke_script = state
                .register_master_script
                .as_deref()
                .and_then(|m| resolve_repo_script(m, "heima-device-revoke.sh"));
            match revoke_script {
                Some(script) => {
                    for (id, label, device_key_hash) in needs_script {
                        // Prefer the on-chain hash (works for chain-reconstructed
                        // actors with no ~/.agentkeys/agents/<label>.json record);
                        // fall back to the label-file path for legacy rows.
                        let outcome = match device_key_hash {
                            Some(hash) => revoke_agent_device_by_hash(&script, hash).await,
                            None => revoke_agent_device(&script, label).await,
                        };
                        match outcome {
                            Ok(tx) => {
                                push_audit(
                                    &state,
                                    ApiAuditEvent {
                                        id: format!("e-reset-revoke-{}-{id}", now_unix()),
                                        ts: now_ts_hms(),
                                        actor_id: "master".into(),
                                        actor: "master".into(),
                                        kind: "device.revoked".into(),
                                        detail: format!(
                                            "{id} · master-reset fleet teardown · on-chain \
                                             revokeAgentDevice{}",
                                            tx.as_ref()
                                                .map(|h| format!(" tx={h}"))
                                                .unwrap_or_else(|| " (already revoked)".into())
                                        ),
                                        chip: "revoke".into(),
                                        sev: "bad".into(),
                                        tx_hash: None,
                                        audit_envelope_hashes: None,
                                    },
                                )
                                .await;
                                agents_revoked.push(serde_json::json!({
                                    "id": id, "label": label, "tx_hash": tx,
                                }));
                            }
                            Err(e) => fleet_failures.push(format!("revoke {label}: {e}")),
                        }
                    }
                }
                None => fleet_failures.push(format!(
                    "{} paired agent(s) NOT revoked on chain: chain not configured (no \
                     --register-master-script / heima-device-revoke.sh) — revoke them from the \
                     actor pages once the chain is wired",
                    needs_script.len()
                )),
            }
        }
    }

    // (0c) Local fleet clear: actors + their caps + the K11 enroll store, so a
    // re-onboarded master starts with a clean slate and `GET /v1/onboarding/state`
    // reports `k11: "none"` (the enroll record described a credential whose
    // binding this reset just destroyed). NO K11 regeneration happens here — a
    // passkey can only be minted by the browser at the next onboarding, and the
    // OS passkey can only be deleted manually.
    let actors_cleared = {
        let mut guard = state.actors.write().await;
        let n = guard.len();
        guard.clear();
        n
    };
    state.caps.write().await.clear();
    // #233: invalidate the chain sync — the next actor read re-reconciles the
    // (now torn-down) chain instead of trusting this process's cleared map.
    invalidate_fleet_sync(&state);
    {
        let mut enroll = state.enroll.write().await;
        enroll.pending.clear();
        enroll.registered.clear();
    }
    let fleet = serde_json::json!({
        "pending_declined": pending_declined,
        "agents_revoked": agents_revoked,
        "actors_cleared": actors_cleared,
        "k11_enroll_cleared": true,
        "failures": fleet_failures,
    });

    // (1) ON-CHAIN unbind via the deployer-owned resetMaster.
    let onchain = match (state.register_master_script.clone(), operator_omni.clone()) {
        (Some(script), Some(omni)) => match reset_master_onchain(&script, &omni).await {
            Ok(v) if v.get("skipped").is_some() => {
                tracing::info!(target: "agentkeys.daemon.ui_bridge", omni = %omni, "master reset — on-chain already unbound");
                serde_json::json!({ "status": "skipped", "reason": "already-unbound", "operator_omni": omni })
            }
            Ok(v) => {
                let tx = v
                    .get("tx_hash")
                    .and_then(|t| t.as_str())
                    .unwrap_or_default();
                tracing::info!(target: "agentkeys.daemon.ui_bridge", omni = %omni, tx = %tx, "master reset — on-chain operatorMasterWallet cleared");
                serde_json::json!({ "status": "reset", "tx_hash": tx, "operator_omni": omni })
            }
            Err(e) => {
                tracing::warn!(target: "agentkeys.daemon.ui_bridge", omni = %omni, "master reset — on-chain unbind FAILED: {e}");
                serde_json::json!({ "status": "failed", "error": e, "operator_omni": omni })
            }
        },
        (None, _) => {
            serde_json::json!({ "status": "skipped", "reason": "no-register-script-configured" })
        }
        (_, None) => serde_json::json!({ "status": "skipped", "reason": "no-operator-omni-known" }),
    };

    // (2) LOCAL clear (always — even if the on-chain step failed, so the UI isn't stuck).
    *state.registered_master.write().await = None;
    *state.pending_register.write().await = None;
    *state.master_session.write().await = None;
    if let Some(store) = state.master_session_store.as_ref() {
        if let Err(e) = store.clear_all() {
            tracing::warn!("ui-bridge: master reset failed to clear persisted session: {e}");
        }
    }
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        "master reset — local binding cleared; the OS passkey is NOT touched (WebAuthn forbids site deletion)"
    );

    let status = onchain.get("status").and_then(|s| s.as_str());
    let onchain_cleared = status == Some("reset")
        || (status == Some("skipped")
            && onchain.get("reason").and_then(|s| s.as_str()) == Some("already-unbound"));
    let note = if onchain_cleared {
        "local + ON-CHAIN master binding cleared — delete the master passkey in your OS password \
         manager (System Settings ▸ Passwords), then re-onboard with a fresh passkey."
    } else {
        "LOCAL master binding cleared, but the ON-CHAIN binding was NOT cleared (see onchain.error / \
         onchain.reason). Re-onboarding will still fail with SIG_VALIDATION until it is — confirm the \
         registry is VERSION>=0.3 (has resetMaster) and the deployer key is available, then retry, or \
         run scripts/operator/chain/heima-reset-master.sh --operator-omni <omni> manually."
    };

    Json(serde_json::json!({ "ok": true, "onchain": onchain, "note": note, "fleet": fleet }))
}

/// Persist the current master session coordinates to
/// `~/.agentkeys/daemon-<wallet>/master-session.json` and refresh the in-memory
/// `master_session` mirror (issue #220). No-op when persistence is disabled
/// (`master_session_store == None`, e.g. tests) or the session is identity-only
/// (no J1/omni to resume). Best-effort: a disk error is logged, never fatal to
/// the live in-memory session.
async fn persist_master_session(state: &UiBridgeState) {
    let Some(store) = state.master_session_store.as_ref() else {
        return;
    };
    let Some(session) = state.onboarding_session.read().await.clone() else {
        return;
    };
    if session.j1.is_empty() || session.omni.is_empty() {
        return; // identity-only — nothing durable to resume
    }
    let omni = agentkeys_backend_client::normalize_omni_0x(&session.omni);
    // device_key_hash: the registered one when K11-finish ran this session, else
    // the deterministic keccak(operator_omni) — the on-chain SidecarRegistry key,
    // so the persisted hash matches what cap-mint resolves with no cached register.
    let device_key_hash = match state.registered_master.read().await.as_ref() {
        Some(rm) => rm.device_key_hash.clone(),
        None => match agentkeys_core::device_crypto::device_key_hash_from_omni(&omni) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("ui-bridge #220: cannot derive device hash to persist: {e}");
                return;
            }
        },
    };
    let created_at_unix = master_session::now_unix();
    let record = PersistedMasterSession {
        schema: 1,
        wallet: session.wallet.clone(),
        email: session.email.clone(),
        operator_omni: omni,
        device_key_hash,
        j1: session.j1.clone(),
        created_at_unix,
        j1_exp_unix: master_session::j1_expiry_for(&session.j1, created_at_unix),
    };
    if let Err(e) = store.save(&record) {
        tracing::warn!("ui-bridge #220: failed to persist master session: {e}");
        return;
    }
    *state.master_session.write().await = Some(record);
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        "issue #220: master session persisted (restart-resumable; zero-prompt while J1 valid)"
    );
}

/// Rehydrate the master session from disk at daemon startup (issue #220). Loads
/// the most-recent persisted record and, when the J1 is still valid, repopulates
/// `onboarding_session` + `registered_master` so the web memory/config pages work
/// with ZERO prompts — no re-onboarding, no `--master-device-key-hash`. An expired
/// J1 still loads the coords into `master_session` (so `/v1/onboarding/state`
/// reports `session: "expired"` and the web app can prompt exactly one passkey
/// re-auth) but leaves `onboarding_session` empty (the dead J1 isn't usable).
/// No-op when persistence is disabled.
pub async fn rehydrate_master_session(state: &UiBridgeState) {
    let Some(store) = state.master_session_store.as_ref() else {
        return;
    };
    let Some(record) = store.load_latest() else {
        return;
    };
    let now = master_session::now_unix();
    let valid = record.j1_valid_at(now);
    if valid {
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: record.email.clone(),
            omni: record.operator_omni.clone(),
            j1: record.j1.clone(),
            wallet: record.wallet.clone(),
        });
        // The device is on chain (SidecarRegistry) under this omni — record it so
        // cap-mint resolves it directly and onboarding-state reports it registered.
        mark_master_registered(
            state,
            RegisteredMaster {
                device_key_hash: record.device_key_hash.clone(),
                operator_omni: record.operator_omni.clone(),
                tx_hash: None,
                // The account address isn't persisted in the #220 session record;
                // the #233 chain reconciliation backfills it from
                // operatorMasterWallet on the first actor read after restart.
                account: None,
            },
        )
        .await;
        tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            wallet = %record.wallet,
            "issue #220: master session rehydrated from disk (valid J1) — zero-prompt restore"
        );
    } else {
        tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            wallet = %record.wallet,
            "issue #220: master session found on disk but J1 expired — one passkey re-auth restores it (no re-onboarding)"
        );
    }
    *state.master_session.write().await = Some(record);
}

async fn enroll_begin(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<EnrollBeginRequest>,
) -> Result<Json<EnrollBeginResponse>, (StatusCode, Json<ErrorBody>)> {
    if req.username.trim().is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "username required",
            "missing-username",
        ));
    }
    let user_id = Uuid::new_v4();
    let user_id_str = user_id.to_string();
    let (ccr, reg_state) = state
        .webauthn
        .start_passkey_registration(user_id, &req.username, &req.display_name, None)
        .map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("webauthn start failed: {e}"),
                "webauthn-start-failed",
            )
        })?;

    let mut guard = state.enroll.write().await;
    guard.pending.insert(user_id_str.clone(), reg_state);

    Ok(Json(EnrollBeginResponse {
        user_id: user_id_str,
        creation_options: serde_json::to_value(&ccr).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encode failed: {e}"),
                "encode-failed",
            )
        })?,
    }))
}

async fn enroll_finish(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<EnrollFinishRequest>,
) -> Result<Json<EnrollFinishResponse>, (StatusCode, Json<ErrorBody>)> {
    // Issue #196: pull the raw attestationObject (b64url) out of the credential
    // JSON BEFORE `from_value` consumes it — the on-chain register shell-out
    // forwards the K11 pubkey + rpIdHash extracted from it (the web path has no
    // disk K11 file). Always present in a real registration response.
    let attestation_object_b64 = req
        .credential
        .get("response")
        .and_then(|r| r.get("attestationObject"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let reg =
        serde_json::from_value::<RegisterPublicKeyCredential>(req.credential).map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                format!("malformed credential: {e}"),
                "credential-malformed",
            )
        })?;

    let reg_state = {
        let mut guard = state.enroll.write().await;
        guard.pending.remove(&req.user_id).ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "no pending enrollment for this user_id",
                "no-pending",
            )
        })?
    };

    let passkey = state
        .webauthn
        .finish_passkey_registration(&reg, &reg_state)
        .map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                format!("attestation rejected: {e}"),
                "attestation-rejected",
            )
        })?;

    let credential_id_b64 = base64url_encode(passkey.cred_id().as_ref());
    let registered_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut guard = state.enroll.write().await;
    guard.registered.insert(
        req.user_id.clone(),
        RegisteredCredential {
            credential_id_b64: credential_id_b64.clone(),
            registered_at_unix,
        },
    );

    drop(guard);

    // Issue #196: submit registerFirstMasterDevice on chain (un-stub
    // chain_tx_hash). The device is registered under the daemon's SESSION omni —
    // cap.rs forces device.operator_omni == J1.omni_account == the cap-mint
    // operator_omni, so a master-self memory cap resolves exactly this device.
    // The deployer key signs the tx (msg.sender); the K11 pubkey is the browser
    // passkey just enrolled. Best-effort: a chain failure does NOT void the
    // passkey enrollment — it surfaces in `chain_error` so the operator funds +
    // retries instead of hitting a confusing cap-mint failure at plant time.
    let build = finish_chain_register(
        &state,
        &credential_id_b64,
        attestation_object_b64.as_deref(),
    )
    .await;

    Ok(Json(EnrollFinishResponse {
        credential_id: credential_id_b64,
        registered_at_unix,
        chain_tx_hash: build.chain_tx_hash,
        chain: build.chain,
        chain_error: build.chain_error,
        register_userop_hash: build.register_userop_hash,
        register_account: build.register_account,
    }))
}

/// K11-finish → on-chain register glue (issue #196). Returns
/// `(chain_tx_hash, chain_status, chain_error)` and never errors out the
/// enrollment (the passkey is already persisted). Chain registration is skipped
/// — `("none", None)` with no error — when no register script is configured
/// (dev / no-infra). A missing session or a shell-out failure returns a
/// `chain_error` so the web UI can surface "fund + retry".
/// #225 / E7 build-phase result. `chain`: `"register-pending"` (account built;
/// the browser must sign `register_userop_hash` next via `/v1/master/register/submit`),
/// `"master-registered"` (idempotent skip — the operator already has a master),
/// or `"none"` (no script / error in `chain_error`).
struct ChainRegisterBuild {
    register_userop_hash: Option<String>,
    register_account: Option<String>,
    chain_tx_hash: Option<String>,
    chain: String,
    chain_error: Option<String>,
}

async fn finish_chain_register(
    state: &SharedUiBridgeState,
    _credential_id_b64url: &str,
    attestation_object_b64: Option<&str>,
) -> ChainRegisterBuild {
    let none = |chain: &str, err: Option<String>| ChainRegisterBuild {
        register_userop_hash: None,
        register_account: None,
        chain_tx_hash: None,
        chain: chain.to_string(),
        chain_error: err,
    };
    // On-chain register needs EITHER a broker (the #278 D6 sponsored path) OR the
    // legacy register script. Neither configured ⇒ a CLEAN skip (dev / no-infra),
    // no error. (The per-path requirement is enforced below: the broker path needs
    // broker_url; the legacy fallback needs register_master_script.)
    if state.broker_url.is_none() && state.register_master_script.is_none() {
        return none("none", None);
    }
    let Some(session) = state.onboarding_session.read().await.clone() else {
        let msg = "K11 enrolled but no onboarding session — verify email first, \
                   then re-enroll to register the master device on chain"
            .to_string();
        tracing::warn!("ui-bridge register-master: {msg}");
        return none("none", Some(msg));
    };
    if session.omni.is_empty() {
        return none(
            "none",
            Some("onboarding session has no EVM omni (managed-wallet attestation skipped)".into()),
        );
    }
    let Some(att_b64) = attestation_object_b64 else {
        return none(
            "none",
            Some("credential missing response.attestationObject — cannot derive K11 pubkey".into()),
        );
    };
    let k11 = match decode_web_k11(att_b64) {
        Ok(k) => k,
        Err(e) => return none("none", Some(format!("K11 pubkey extract: {e}"))),
    };
    let (pub_x, pub_y) = match split_cose_xy(&k11.cose_pubkey_hex) {
        Ok(xy) => xy,
        Err(e) => return none("none", Some(e)),
    };
    let cred_id_hash = match master_cred_id_hash_hex(&session.omni) {
        Ok(h) => h,
        Err(e) => return none("none", Some(format!("cred-id-hash: {e}"))),
    };
    let omni0x = if session.omni.starts_with("0x") {
        session.omni.clone()
    } else {
        format!("0x{}", session.omni)
    };

    // #278 D6 — when a broker is configured, collapse the register into ONE
    // paymaster-sponsored UserOp via the broker's /v1/register/build (initCode +
    // executeBatch([registerFirstMasterDevice])) instead of the deployer-funded
    // 3-tx shell-out below. The browser signs the SAME userOpHash next; submit
    // forwards to /v1/register/submit. The broker derives the omni-keyed values
    // (cred-id / salt / device-key, actor==operator) and skip-gates 409 itself.
    if let Some(broker) = state.broker_url.clone() {
        let device_key_hash = master_device_key_hash_hex(&session.omni).unwrap_or_default();
        let body = serde_json::json!({
            "operator_omni": omni0x,
            "owner_pubkey_x": pub_x,
            "owner_pubkey_y": pub_y,
            "rpid_hash": k11.rp_id_hash_hex,
            "roles": 7, // CAP_MINT | RECOVERY | SCOPE_MGMT (§9 stage 4)
        });
        match broker_post_json(&broker, "/v1/register/build", &session.j1, &body).await {
            Ok((st, v)) if st.is_success() => {
                let user_op = v.get("user_op").cloned().unwrap_or(serde_json::Value::Null);
                let userop_hash = v
                    .get("user_op_hash")
                    .and_then(|h| h.as_str())
                    .unwrap_or_default()
                    .to_string();
                // sender IS the predicted CREATE2 master account (broker sets it).
                let account = user_op
                    .get("sender")
                    .and_then(|s| s.as_str())
                    .unwrap_or_default()
                    .to_string();
                if userop_hash.is_empty() || account.is_empty() {
                    return none(
                        "none",
                        Some(format!(
                            "broker /v1/register/build: no user_op_hash/sender: {v}"
                        )),
                    );
                }
                *state.pending_register.write().await = Some(PendingMasterRegister {
                    state_file: String::new(),
                    broker_user_op: Some(user_op),
                    account: account.clone(),
                    cred_id_hash,
                    device_key_hash,
                    operator_omni: omni0x.clone(),
                });
                tracing::info!(
                    target: "agentkeys.daemon.ui_bridge",
                    account = %account,
                    "#278 D6: one-op sponsored master register built at the broker — awaiting the browser signature"
                );
                return ChainRegisterBuild {
                    register_userop_hash: Some(userop_hash),
                    register_account: Some(account),
                    chain_tx_hash: None,
                    chain: "register-pending".to_string(),
                    chain_error: None,
                };
            }
            // 409 = first-master-only: the operator already has a master on chain.
            Ok((st, _)) if st == StatusCode::CONFLICT => {
                mark_master_registered(
                    state,
                    RegisteredMaster {
                        device_key_hash,
                        operator_omni: omni0x.clone(),
                        tx_hash: None,
                        account: None,
                    },
                )
                .await;
                persist_master_session(state).await;
                return ChainRegisterBuild {
                    register_userop_hash: None,
                    register_account: None,
                    chain_tx_hash: None,
                    chain: "master-registered".to_string(),
                    chain_error: None,
                };
            }
            // Any OTHER broker failure (5xx, route/paymaster misconfig, network): a
            // broker IS configured, so it owns the register path — surface its failure
            // LOUDLY + actionably. Do NOT silently fall back to the deployer-funded
            // shell-out: that would hide a broken D6 sponsored register, re-introduce
            // deployer txs without anyone noticing, and let onboarding "succeed" while
            // masking the real error (stale-green). The operator fixes the broker
            // (route / paymaster / deposit), then retries — the master is NOT bound, so
            // downstream cap flows would fail `device_not_active` regardless.
            Ok((st, v)) => {
                tracing::error!(
                    target: "agentkeys.daemon.ui_bridge",
                    "#278 D6: broker /v1/register/build FAILED {st}: {v}"
                );
                return none(
                    "none",
                    Some(format!(
                        "master register failed at the broker (/v1/register/build → {st}): {v} \
                         — fix the broker register route / paymaster, then retry (the master is \
                         NOT bound on chain)"
                    )),
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "agentkeys.daemon.ui_bridge",
                    "#278 D6: broker /v1/register/build unreachable: {e}"
                );
                return none(
                    "none",
                    Some(format!(
                        "master register could not reach the broker: {e} — retry"
                    )),
                );
            }
        }
    }

    // Legacy deployer-funded shell-out path (reached only when no broker is
    // configured — the D6 broker path above returns first). THIS path needs the
    // register script; a broker-only daemon never gets here.
    let Some(script) = state.register_master_script.clone() else {
        return none("none", None);
    };
    let state_file = register_state_file(&session.omni);

    // BUILD: deploy the P256Account + fund the 5-HEI deposit + assemble the
    // register UserOp (deployer pays gas; the passkey authorizes). Returns the
    // userOpHash the browser signs, OR a {skipped:"already-registered"}.
    let json = match register_master_build(
        &script,
        &omni0x,
        &pub_x,
        &pub_y,
        &cred_id_hash,
        &k11.rp_id_hash_hex,
        &state_file,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("ui-bridge register-master build failed: {e}");
            return none("none", Some(e));
        }
    };

    let device_key_hash = json
        .get("device_key_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let account = json
        .get("account")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let operator_omni = json
        .get("operator_omni")
        .and_then(|v| v.as_str())
        .unwrap_or(&omni0x)
        .to_string();

    // Idempotent skip: the operator already has a master on chain (no re-register).
    if json.get("skipped").is_some() {
        mark_master_registered(
            state,
            RegisteredMaster {
                device_key_hash,
                operator_omni,
                tx_hash: None,
                account: (!account.is_empty()).then_some(account.clone()),
            },
        )
        .await;
        persist_master_session(state).await;
        return ChainRegisterBuild {
            register_userop_hash: None,
            register_account: (!account.is_empty()).then_some(account),
            chain_tx_hash: None,
            chain: "master-registered".to_string(),
            chain_error: None,
        };
    }

    // Built: stash the pending register; the browser signs userop_hash next.
    let userop_hash = json
        .get("userop_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if userop_hash.is_empty() || account.is_empty() {
        return none(
            "none",
            Some(format!("build returned no userop_hash/account: {json}")),
        );
    }
    *state.pending_register.write().await = Some(PendingMasterRegister {
        state_file,
        broker_user_op: None,
        account: account.clone(),
        cred_id_hash,
        device_key_hash,
        operator_omni,
    });
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        account = %account,
        "E7: master P256Account built + funded — awaiting the browser register signature"
    );
    ChainRegisterBuild {
        register_userop_hash: Some(userop_hash),
        register_account: Some(account),
        chain_tx_hash: None,
        chain: "register-pending".to_string(),
        chain_error: None,
    }
}

/// Split a SEC1 uncompressed COSE pubkey (`04 || X || Y`, 130 hex) → (0xX, 0xY).
fn split_cose_xy(cose_pubkey_hex: &str) -> Result<(String, String), String> {
    let h = cose_pubkey_hex.trim().trim_start_matches("0x");
    if h.len() != 130 || !h.starts_with("04") {
        return Err(format!(
            "cose pubkey expected 130 hex (04||X||Y); got {} chars",
            h.len()
        ));
    }
    Ok((format!("0x{}", &h[2..66]), format!("0x{}", &h[66..130])))
}

/// `master_cred_id_hash(omni)` as `0x`-hex — the P256Account signer key (matches
/// the accept's assertion; NOT `keccak(rawId)`).
fn master_cred_id_hash_hex(operator_omni: &str) -> Result<String, String> {
    let bare = operator_omni.trim().trim_start_matches("0x");
    let bytes = hex::decode(bare).map_err(|e| format!("omni hex: {e}"))?;
    let omni: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "omni must be 32 bytes".to_string())?;
    Ok(format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::master_cred_id_hash(&omni))
    ))
}

/// `master_device_key_hash(omni)` as `0x`-hex — `keccak256(raw omni bytes)`, the
/// first master's `deviceKeyHash` (#278 D6 broker path; matches the broker-derived
/// value + `_erc4337_lib.sh`'s `cast keccak "0x$OMNI"`).
fn master_device_key_hash_hex(operator_omni: &str) -> Result<String, String> {
    let bare = operator_omni.trim().trim_start_matches("0x");
    let bytes = hex::decode(bare).map_err(|e| format!("omni hex: {e}"))?;
    let omni: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "omni must be 32 bytes".to_string())?;
    Ok(format!(
        "0x{}",
        hex::encode(agentkeys_core::erc4337::master_device_key_hash(&omni))
    ))
}

/// Per-omni temp state-file path for the register `build`→`submit` handoff.
fn register_state_file(operator_omni: &str) -> String {
    let short: String = operator_omni
        .trim_start_matches("0x")
        .chars()
        .take(16)
        .collect();
    std::env::temp_dir()
        .join(format!("agentkeys-register-{short}"))
        .to_string_lossy()
        .into_owned()
}

/// Decode the attestationObject (b64url) → the on-chain K11 material (pubkey +
/// rpIdHash). Reuses the CLI's tested CBOR/COSE parser.
fn decode_web_k11(
    att_obj_b64url: &str,
) -> Result<agentkeys_cli::k11_webauthn::WebK11Material, String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let bytes = URL_SAFE_NO_PAD
        .decode(att_obj_b64url)
        .map_err(|e| format!("attestationObject not valid b64url: {e}"))?;
    agentkeys_cli::k11_webauthn::parse_web_k11(&bytes).map_err(|e| e.to_string())
}

/// Shell out to `heima-register-first-master.sh` (wire-real-paths.md §4.2) to
/// submit `registerFirstMasterDevice` under the session omni, signed by the
/// local deployer key (msg.sender). Parses the trailing JSON line for the
/// device_key_hash (what cap-mint sends) + tx_hash (None on idempotent skip).
async fn run_register_script(script: &str, args: &[&str]) -> Result<serde_json::Value, String> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("spawn {script}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Surface the last few stderr lines (the script logs `fail <reason>`).
        let tail: String = stderr
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!("register script exited {}: {tail}", output.status));
    }
    // The script prints human logs on stderr and a single JSON line on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("register script produced no JSON on stdout: {stdout}"))?;
    serde_json::from_str(json_line.trim()).map_err(|e| format!("register JSON parse: {e}"))
}

/// E7 BUILD: `erc4337-register-master.sh build` — deploy the P256Account + fund
/// its EntryPoint deposit (5 HEI, deployer-paid) + assemble the register UserOp.
/// Returns the JSON: `{userop_hash, account, device_key_hash}` OR
/// `{skipped:"already-registered", …}` (operator already has a master).
async fn register_master_build(
    script: &str,
    operator_omni: &str,
    pub_x: &str,
    pub_y: &str,
    cred_id_hash: &str,
    rpid_hash: &str,
    state_file: &str,
) -> Result<serde_json::Value, String> {
    run_register_script(
        script,
        &[
            "build",
            "--operator-omni",
            operator_omni,
            "--pubx",
            pub_x,
            "--puby",
            pub_y,
            "--cred-id-hash",
            cred_id_hash,
            "--rpid-hash",
            rpid_hash,
            "--state-file",
            state_file,
        ],
    )
    .await
}

/// E7 SUBMIT: `erc4337-register-master.sh submit` — encode the browser assertion
/// into the UserOp signature + `EntryPoint.handleOps`. Returns `{tx_hash, account, …}`.
#[allow(clippy::too_many_arguments)]
async fn register_master_submit(
    script: &str,
    state_file: &str,
    cred_id_hash: &str,
    authdata: &str,
    clientdata: &str,
    challenge_loc: &str,
    r: &str,
    s: &str,
) -> Result<serde_json::Value, String> {
    run_register_script(
        script,
        &[
            "submit",
            "--state-file",
            state_file,
            "--cred-id-hash",
            cred_id_hash,
            "--authdata",
            authdata,
            "--clientdata",
            clientdata,
            "--challenge-loc",
            challenge_loc,
            "--r",
            r,
            "--s",
            s,
        ],
    )
    .await
}

/// `POST /v1/master/register/submit` body (#225 / E7).
#[derive(Debug, Deserialize)]
pub struct MasterRegisterSubmitRequest {
    pub assertion: BrowserRegisterAssertion,
}

/// The raw browser `get()` assertion (base64url), exactly as
/// `apps/parent-control/lib/webauthn.ts::getAssertionOverHash` emits it over the
/// register `userop_hash`.
#[derive(Debug, Deserialize)]
pub struct BrowserRegisterAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    // `credential_id` (b64url) may also be present on the wire (serde ignores it) —
    // the signer key is `cred_id_hash` from the pending build, not the raw id.
}

/// `POST /v1/master/register/submit` (#225 / E7) — phase 2 of the master register.
/// The browser passkey signed the `userop_hash` from K11-finish's build; encode
/// the assertion into the UserOp signature and land `EntryPoint.handleOps`, binding
/// `operatorMasterWallet[omni]` = the master P256Account.
async fn master_register_submit(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<MasterRegisterSubmitRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let pending = state.pending_register.read().await.clone().ok_or_else(|| {
        err(
            StatusCode::CONFLICT,
            "no master register in flight — finish K11 enrollment (build) first",
            "no-pending-register",
        )
    })?;

    // #278 D6: a broker-built pending register submits the ONE sponsored op to the
    // broker's /v1/register/submit (the shared accept relay) — the browser assertion
    // rides through verbatim; the broker encodes it into the UserOp signature and
    // lands EntryPoint.handleOps (deploying the account from the initCode + running
    // registerFirstMasterDevice in one tx).
    if let Some(user_op) = pending.broker_user_op.clone() {
        let broker = state.broker_url.clone().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "no broker configured for the D6 register submit",
                "no-broker",
            )
        })?;
        let j1 = match state.onboarding_session.read().await.as_ref() {
            Some(s) if !s.j1.is_empty() => s.j1.clone(),
            _ => {
                return Err(err(
                    StatusCode::FORBIDDEN,
                    "no master session",
                    "no-session",
                ))
            }
        };
        let a = &req.assertion;
        let body = serde_json::json!({
            "user_op": user_op,
            "assertion": {
                "authenticator_data": &a.authenticator_data,
                "client_data_json": &a.client_data_json,
                "signature": &a.signature,
                // the broker derives credIdHash from the verified J1 omni; raw id unused.
                "credential_id": "",
            },
        });
        let (resp, parsed) =
            forward_to_broker_value(&broker, "/v1/register/submit", &j1, &body).await;
        if !resp.status().is_success() {
            // Surface the broker's REAL reason — it emits a precise error (e.g.
            // "handleOps did not broadcast: bundler eth_sendUserOperation: <reason>"
            // or a decoded handleOps revert). The old generic fallback hid every
            // Base register failure behind one opaque line. Forward the broker's
            // status too, so a 409 already-registered / 503 sponsored-only doesn't
            // masquerade as a 502 gateway error.
            let status = resp.status();
            let detail = parsed.map(|v| v.to_string()).unwrap_or_else(|| {
                "broker /v1/register/submit failed (broker returned an empty or non-JSON body)"
                    .into()
            });
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                account = %pending.account,
                %status,
                detail = %detail,
                "#278 D6: master register submit FAILED at broker — UserOp not broadcast"
            );
            return Err(err(status, detail, "register-submit-failed"));
        }
        let v = parsed.unwrap_or(serde_json::Value::Null);
        let (tx_hash, _) = submit_receipts(&v);
        // CONFIRMATION GATE: the reused accept relay returns `pending: true` (and no
        // tx_hash) when its receipt poll times out — the op MAY still land later. Do
        // NOT persist the bound master on an unconfirmed op, or /v1/onboarding/state
        // would falsely report `master-registered` and downstream cap/UI flows would
        // run against an UNbound operatorMasterWallet. (The legacy shell path
        // post-verified isActive on chain before reporting success — keep that
        // guarantee.) Keep the register pending; the browser keeps polling onboarding
        // state, and a retry (or a session rehydrate, which re-derives from chain)
        // confirms it.
        let unconfirmed =
            v.get("pending").and_then(|p| p.as_bool()).unwrap_or(false) || tx_hash.is_none();
        if unconfirmed {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                account = %pending.account,
                "#278 D6: register broadcast but receipt UNCONFIRMED — keeping it pending, NOT marking bound"
            );
            return Ok(Json(serde_json::json!({
                "ok": true,
                "chain": "register-pending",
                "pending": true,
                "account": pending.account,
                "device_key_hash": pending.device_key_hash,
                "user_op_hash": v.get("user_op_hash").cloned().unwrap_or(serde_json::Value::Null),
            })));
        }
        let registered = RegisteredMaster {
            device_key_hash: pending.device_key_hash.clone(),
            operator_omni: pending.operator_omni.clone(),
            tx_hash: tx_hash.clone(),
            account: Some(pending.account.clone()),
        };
        tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            account = %pending.account,
            tx = tx_hash.as_deref().unwrap_or("(pending)"),
            "#278 D6: one-op sponsored master register landed — operatorMasterWallet bound"
        );
        let out = serde_json::json!({
            "ok": true,
            "chain": "master-registered",
            "tx_hash": tx_hash,
            "account": pending.account,
            "device_key_hash": pending.device_key_hash,
            "user_op_hash": v.get("user_op_hash").cloned().unwrap_or(serde_json::Value::Null),
        });
        mark_master_registered(&state, registered).await;
        *state.pending_register.write().await = None;
        persist_master_session(&state).await;
        return Ok(Json(out));
    }

    let script = state.register_master_script.clone().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "on-chain register not configured (no --register-master-script)",
            "no-register-script",
        )
    })?;

    let a = req.assertion;
    let dec = agentkeys_cli::k11_webauthn::decode_web_userop_assertion(
        &a.authenticator_data,
        &a.client_data_json,
        &a.signature,
    )
    .map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("assertion decode: {e}"),
            "assertion-decode",
        )
    })?;

    let loc = dec.challenge_location.to_string();
    let json = register_master_submit(
        &script,
        &pending.state_file,
        &pending.cred_id_hash,
        &dec.authenticator_data_hex,
        &dec.client_data_json_hex,
        &loc,
        &dec.r_hex,
        &dec.s_hex,
    )
    .await
    .map_err(|e| err(StatusCode::BAD_GATEWAY, e, "register-submit-failed"))?;

    let registered = RegisteredMaster {
        device_key_hash: pending.device_key_hash.clone(),
        operator_omni: pending.operator_omni.clone(),
        tx_hash: json
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .map(String::from),
        account: Some(pending.account.clone()),
    };
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        account = %pending.account,
        operator_omni = %registered.operator_omni,
        tx = registered.tx_hash.as_deref().unwrap_or("(none)"),
        "E7: master P256Account registered — operatorMasterWallet bound"
    );
    let resp = serde_json::json!({
        "ok": true,
        "chain": "master-registered",
        "tx_hash": registered.tx_hash,
        "account": pending.account,
        "device_key_hash": pending.device_key_hash,
    });
    mark_master_registered(&state, registered).await;
    *state.pending_register.write().await = None;
    persist_master_session(&state).await;
    Ok(Json(resp))
}

fn base64url_encode(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ts_hms() -> String {
    // HH:MM:SS in UTC for audit event timestamps. Operator-facing only —
    // chain timestamps are independent.
    let now = now_unix();
    let h = (now / 3600) % 24;
    let m = (now / 60) % 60;
    let s = now % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

// ─── Read endpoints ────────────────────────────────────────────────────

// ─── #233: reconstruct the actor tree from the CHAIN ───────────────────────
//
// The in-memory `state.actors` map is populated during onboarding/pairing and
// lost on a daemon restart, while the chain still holds the whole fleet
// (`operatorMasterWallet[omni]` + `getOperatorDevices(omni)`). These helpers
// rebuild it lazily so the actor page — and the #243 reset fleet teardown —
// reflect on-chain truth, not whatever this process happened to witness.

/// One `SidecarRegistry.DeviceEntry` row, reduced to what the actor tree needs.
#[derive(Clone, Debug)]
struct ChainDevice {
    device_key_hash: String,
    operator_omni: String,
    actor_omni: String,
    /// `TIER_MASTER = 1`, `TIER_AGENT = 2` (SidecarRegistry constants).
    tier: u8,
    revoked: bool,
}

fn chain_word(raw: &[u8], i: usize) -> Result<[u8; 32], String> {
    let (start, end) = (i * 32, i * 32 + 32);
    if raw.len() < end {
        return Err(format!(
            "short ABI return: need word {i} ({end} bytes), got {}",
            raw.len()
        ));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&raw[start..end]);
    Ok(w)
}

fn chain_selector(sig: &str) -> String {
    hex::encode(&agentkeys_core::device_crypto::keccak256(sig.as_bytes())[..4])
}

/// Minimal JSON-RPC `eth_call` against the chain profile's HTTP RPC.
async fn daemon_eth_call(rpc: &str, to: &str, data: &str) -> Result<Vec<u8>, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{ "to": to, "data": data }, "latest"]
    });
    let resp: serde_json::Value = reqwest::Client::new()
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("eth_call send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("eth_call decode: {e}"))?;
    let hexs = resp
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| format!("eth_call no result: {resp}"))?;
    hex::decode(hexs.trim_start_matches("0x")).map_err(|e| format!("eth_call result hex: {e}"))
}

/// `eth_getCode(addr) != 0x` — true iff `addr` is a deployed contract. The
/// #260 reset guard reads this on `operatorMasterWallet[omni]`: a passkey
/// P256Account master (has code) means NO EOA — incl. the deployer script —
/// can sign `revokeAgentDevice`, so still-bound agents need the Touch-ID
/// fleet revoke instead.
async fn daemon_eth_address_has_code(rpc: &str, addr_0x: &str) -> Result<bool, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "eth_getCode",
        "params": [addr_0x, "latest"]
    });
    let resp: serde_json::Value = reqwest::Client::new()
        .post(rpc)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("eth_getCode send: {e}"))?
        .json()
        .await
        .map_err(|e| format!("eth_getCode decode: {e}"))?;
    let code = resp
        .get("result")
        .and_then(|r| r.as_str())
        .ok_or_else(|| format!("eth_getCode no result: {resp}"))?;
    Ok(code != "0x" && !code.is_empty())
}

/// Parse a `getOperatorDevices(bytes32) -> bytes32[]` return (offset, len, items).
fn parse_device_hashes(raw: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    let len = u64::from_be_bytes(chain_word(raw, 1)?[24..32].try_into().unwrap()) as usize;
    (0..len).map(|i| chain_word(raw, 2 + i)).collect()
}

/// Parse a `getDevice(bytes32) -> DeviceEntry` return (11 static words:
/// operatorOmni, actorOmni, k11CredId, k11RpIdHash, k11PubX, k11PubY, tier,
/// roles, registeredAt, lastSignCount, revoked).
fn parse_device_entry(raw: &[u8], device_key_hash: &[u8; 32]) -> Result<ChainDevice, String> {
    Ok(ChainDevice {
        device_key_hash: format!("0x{}", hex::encode(device_key_hash)),
        operator_omni: format!("0x{}", hex::encode(chain_word(raw, 0)?)),
        actor_omni: format!("0x{}", hex::encode(chain_word(raw, 1)?)),
        tier: chain_word(raw, 6)?[31],
        revoked: chain_word(raw, 10)?[31] != 0,
    })
}

/// The SidecarRegistry address from the compiled-in chain profile.
fn registry_address(state: &UiBridgeState) -> Option<String> {
    state
        .chain_profile
        .contracts
        .iter()
        .find(|c| c.name == "SidecarRegistry")
        .map(|c| c.address.clone())
}

/// The AgentKeysScope address from the compiled-in chain profile.
fn scope_contract_address(state: &UiBridgeState) -> Option<String> {
    state
        .chain_profile
        .contracts
        .iter()
        .find(|c| c.name == "AgentKeysScope")
        .map(|c| c.address.clone())
}

/// Parse an `AgentKeysScope.getScope(bytes32,bytes32) -> Scope` return:
/// dynamic struct `{ bytes32[] services; bool readOnly; u128 ×3; u32
/// periodSeconds; u64 updatedAt; bool exists }` — w0 = struct offset; the
/// 8-word head holds (services_offset, readOnly, …, exists); the services
/// array (len + items) sits at `struct + services_offset`. Returns
/// `(service_hashes, read_only, exists)`.
fn parse_scope_return(raw: &[u8]) -> Result<(Vec<[u8; 32]>, bool, bool), String> {
    let struct_off =
        u64::from_be_bytes(chain_word(raw, 0)?[24..32].try_into().unwrap()) as usize / 32;
    let services_off =
        u64::from_be_bytes(chain_word(raw, struct_off)?[24..32].try_into().unwrap()) as usize / 32;
    let read_only = chain_word(raw, struct_off + 1)?[31] != 0;
    let exists = chain_word(raw, struct_off + 7)?[31] != 0;
    let len_idx = struct_off + services_off;
    let len = u64::from_be_bytes(chain_word(raw, len_idx)?[24..32].try_into().unwrap()) as usize;
    let services = (0..len)
        .map(|i| chain_word(raw, len_idx + 1 + i))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((services, read_only, exists))
}

/// The web UI's core memory namespaces (`apps/parent-control` Namespace type).
/// Scope hashes are `keccak256("memory:<ns>")` — the SAME encoding the broker
/// accept + `heima-scope-set.sh` write (the terminology rule at the byte level).
const SCOPE_NAMESPACES: [&str; 4] = ["personal", "family", "work", "travel"];

/// Mirror the ON-CHAIN scope grant into an actor's `scope` map (the permission
/// panel's data source). The chain is the source of truth for scope — without
/// this, a granted agent showed DENY on every namespace because nothing ever
/// populated the local map from `AgentKeysScope` (real 2026-06-10 incident).
///
/// Also returns the **unmatched** on-chain service ids (`0x`-hex keccak hashes
/// that aren't `memory:<known-ns>` — e.g. `cred:openrouter` from the accept, or
/// a custom namespace). The #248 panel commit is a set-REPLACE `setScope`, so
/// the web must echo these back (`preserve_service_ids`) or a memory-toggle
/// commit would silently wipe the agent's credential grants.
async fn fetch_actor_scope_from_chain(
    rpc: &str,
    scope_contract: &str,
    operator_omni_0x: &str,
    actor_omni_0x: &str,
) -> Result<(Option<HashMap<String, ApiScopeBits>>, Vec<String>), String> {
    let bare = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
    let (op, act) = (bare(operator_omni_0x), bare(actor_omni_0x));
    if op.len() != 64 || act.len() != 64 {
        return Err(format!("bad omni for scope read: {op} / {act}"));
    }
    let data = format!("0x{}{op}{act}", chain_selector("getScope(bytes32,bytes32)"));
    let raw = daemon_eth_call(rpc, scope_contract, &data).await?;
    let (services, _read_only, exists) = parse_scope_return(&raw)?;
    if !exists || services.is_empty() {
        return Ok((None, Vec::new()));
    }
    Ok(classify_scope_hashes(&services))
}

/// Map raw on-chain scope `serviceHash`es into the per-namespace `ApiScopeBits` the
/// permission panel renders, plus the **unmatched** hashes (`unknown`) the panel must
/// echo back on a set-replace commit so they aren't wiped. PURE (no chain) so the
/// shared-read vs inbox-write distinction is unit-testable: a `keccak("memory:<ns>")`
/// sets `read` (read the master's shared memory), a `keccak("inbox:<ns>")` sets `write`
/// (suggest into the master's inbox — the ONLY contribution path, never a direct
/// shared-memory write), and anything else (e.g. `cred:<service>`) is preserved verbatim.
fn classify_scope_hashes(
    services: &[[u8; 32]],
) -> (Option<HashMap<String, ApiScopeBits>>, Vec<String>) {
    let known_mem: Vec<([u8; 32], &str)> = SCOPE_NAMESPACES
        .iter()
        .map(|ns| {
            (
                agentkeys_core::device_crypto::keccak256(format!("memory:{ns}").as_bytes()),
                *ns,
            )
        })
        .collect();
    // #339 — the DISTINCT inbox-write grant per namespace (`inbox:<ns>`). A separate
    // keccak from `memory:<ns>`, so the panel can NAME it (the `write` bit) instead of
    // dumping it into the blind-preserve `unknown` set where the UI can't toggle it.
    let known_inbox: Vec<([u8; 32], &str)> = SCOPE_NAMESPACES
        .iter()
        .map(|ns| {
            (
                agentkeys_core::device_crypto::keccak256(format!("inbox:{ns}").as_bytes()),
                *ns,
            )
        })
        .collect();
    let mut map: HashMap<String, ApiScopeBits> = HashMap::new();
    let mut unknown = Vec::new();
    for h in services {
        if let Some((_, ns)) = known_mem.iter().find(|(kh, _)| kh == h) {
            map.entry((*ns).to_string()).or_default().read = true;
        } else if let Some((_, ns)) = known_inbox.iter().find(|(kh, _)| kh == h) {
            map.entry((*ns).to_string()).or_default().write = true;
        } else {
            unknown.push(format!("0x{}", hex::encode(h)));
        }
    }
    ((!map.is_empty()).then_some(map), unknown)
}

/// The operator omni this daemon serves: the registered master, else the
/// persisted coords, else the live session (same precedence as master_reset).
async fn held_operator_omni(state: &UiBridgeState) -> Option<String> {
    let from_registered = state
        .registered_master
        .read()
        .await
        .as_ref()
        .map(|rm| rm.operator_omni.clone());
    let from_session = state
        .master_session
        .read()
        .await
        .as_ref()
        .map(|ms| ms.operator_omni.clone());
    let from_onboarding = state
        .onboarding_session
        .read()
        .await
        .as_ref()
        .map(|s| s.omni.clone());
    [from_registered, from_session, from_onboarding]
        .into_iter()
        .flatten()
        .find(|o| !o.is_empty())
        .map(|o| agentkeys_backend_client::normalize_omni_0x(&o))
}

/// Fetch the operator's full device fleet from chain.
async fn fetch_chain_fleet(
    rpc: &str,
    registry: &str,
    operator_omni_0x: &str,
) -> Result<Vec<ChainDevice>, String> {
    let omni_bare = operator_omni_0x.trim_start_matches("0x").to_lowercase();
    if omni_bare.len() != 64 {
        return Err(format!("bad operator omni: {operator_omni_0x}"));
    }
    let data = format!(
        "0x{}{omni_bare}",
        chain_selector("getOperatorDevices(bytes32)")
    );
    let raw = daemon_eth_call(rpc, registry, &data).await?;
    let hashes = parse_device_hashes(&raw)?;
    let mut fleet = Vec::with_capacity(hashes.len());
    for h in hashes {
        let data = format!(
            "0x{}{}",
            chain_selector("getDevice(bytes32)"),
            hex::encode(h)
        );
        let raw = daemon_eth_call(rpc, registry, &data).await?;
        fleet.push(parse_device_entry(&raw, &h)?);
    }
    Ok(fleet)
}

/// Reconstruct + reconcile `state.actors` from the chain (#233). In-memory rows
/// WIN (they carry the richer pairing-time labels/scopes); the chain adds what
/// this process never witnessed: the master row (synthesized from the held
/// coords; its on-chain P256Account address is backfilled into
/// `registered_master.account` for the actor page) and any active agent device
/// with no matching row. Revoked devices are excluded. Returns how many rows
/// were added.
async fn reconcile_actors_from_chain(state: &SharedUiBridgeState) -> Result<usize, String> {
    let Some(omni) = held_operator_omni(state).await else {
        return Ok(0); // nobody onboarded — nothing to reconstruct
    };
    let registry =
        registry_address(state).ok_or("no SidecarRegistry in the chain profile".to_string())?;
    let rpc = state.chain_profile.rpc.http.clone();
    let fleet = fetch_chain_fleet(&rpc, &registry, &omni).await?;

    // The master's P256Account address (operatorMasterWallet[omni]) — backfill
    // it when the in-memory register record lost it (restart), so the actor
    // page shows the real account instead of the register CTA.
    let master_account = fetch_operator_master_wallet(&rpc, &registry, &omni).await;
    if let Some(acc) = master_account.as_ref() {
        let mut rm = state.registered_master.write().await;
        if let Some(rm) = rm.as_mut() {
            if rm.account.is_none() {
                rm.account = Some(acc.clone());
            }
        }
    }

    let norm = |o: &str| o.trim().trim_start_matches("0x").to_lowercase();
    let master_email = state
        .master_session
        .read()
        .await
        .as_ref()
        .map(|m| m.email.clone())
        .filter(|e| !e.is_empty());

    // #424 §1 — the binding manifest is the PRIMARY hydration source for what
    // the chain can't say: each restored row's label, delegate-vs-device kind,
    // and granted service NAMES. Deterministic (no hash-guessing) and
    // independent of the channel registry, which stays the SECONDARY
    // enrichment below. Best-effort: an unreachable Config only skips it.
    let manifest = match ensure_binding_manifest(state).await {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::debug!(
                target: "agentkeys.daemon.ui_bridge",
                "binding manifest unavailable for fleet hydration: {e}"
            );
            None
        }
    };

    let mut guard = state.actors.write().await;
    let known_omnis: std::collections::HashSet<String> =
        guard.values().map(|a| norm(&a.omni_hex)).collect();
    let known_hashes: std::collections::HashSet<String> = guard
        .values()
        .filter_map(|a| a.device_key_hash.as_deref().map(norm))
        .collect();
    let mut added = 0usize;
    for d in fleet.iter().filter(|d| !d.revoked) {
        let is_master = d.tier == 1 || norm(&d.actor_omni) == norm(&d.operator_omni);
        if is_master {
            if !guard.values().any(|a| a.role == "master") {
                guard.insert(
                    "master".into(),
                    ApiActor {
                        id: "master".into(),
                        omni: omni.clone(),
                        omni_hex: omni.clone(),
                        label: master_email.clone().unwrap_or_else(|| "O_master".into()),
                        role: "master".into(),
                        parent: None,
                        derivation: "/".into(),
                        device: "passkey P256Account (restored from chain)".into(),
                        device_pubkey: "K11 passkey".into(),
                        last_active: "restored from chain".into(),
                        status: "ok".into(),
                        vendor: String::new(),
                        k11: true,
                        device_key_hash: Some(d.device_key_hash.clone()),
                        scope: None,
                        scope_unknown_service_ids: None,
                        payment_cap: None,
                        time_window: None,
                        services: None,
                        account_address: None,
                        account_type: None,
                        preset_id: None,
                        memory_ns: None,
                    },
                );
                added += 1;
            }
            continue;
        }
        if known_omnis.contains(&norm(&d.actor_omni))
            || known_hashes.contains(&norm(&d.device_key_hash))
        {
            continue; // the live pairing row is richer — in-memory wins
        }
        // #424 §1 — hydrate the restored row from the binding manifest: real
        // label, device-vs-delegate kind, granted service NAMES. Without an
        // entry (paired before the manifest existed / Config unreachable) the
        // row keeps the placeholder shape and the channel-registry match below
        // may still name its channel grants.
        let entry = manifest
            .as_ref()
            .and_then(|m| m.entry_for(&d.actor_omni, &d.device_key_hash))
            .cloned();
        let short = &norm(&d.actor_omni)[..8];
        let (id, label) = match entry.as_ref().filter(|e| !e.label.is_empty()) {
            Some(e) => (format!("agent-{}", e.label), e.label.clone()),
            None => (format!("agent-0x{short}"), format!("agent 0x{short}…")),
        };
        let is_device = entry.as_ref().is_some_and(|e| e.kind == "device");
        let services = entry
            .as_ref()
            .map(|e| e.granted_service_names.clone())
            .filter(|s| !s.is_empty());
        guard.insert(
            id.clone(),
            ApiActor {
                id,
                omni: d.actor_omni.clone(),
                omni_hex: d.actor_omni.clone(),
                label,
                role: "agent".into(),
                parent: Some("master".into()),
                derivation: String::new(),
                device: match (&entry, is_device) {
                    (Some(_), true) => "channel-endpoint device (§10.2)".into(),
                    (Some(_), false) => "sandbox device (§10.2)".into(),
                    (None, _) => "restored from chain".into(),
                },
                device_pubkey: String::new(),
                last_active: "restored from chain".into(),
                status: "ok".into(),
                vendor: if is_device {
                    "device".into()
                } else {
                    String::new()
                },
                k11: false,
                device_key_hash: Some(d.device_key_hash.clone()),
                scope: None,
                scope_unknown_service_ids: None,
                payment_cap: None,
                time_window: None,
                services,
                preset_id: entry.as_ref().and_then(|e| e.preset_id.clone()),
                memory_ns: entry.as_ref().and_then(|e| e.memory_ns.clone()),
                account_address: None,
                account_type: None,
            },
        );
        added += 1;
    }
    drop(guard);

    // Scope mirror (#243 follow-up, real 2026-06-10 incident): the chain is the
    // source of truth for scope — refresh every agent row's `scope` map from
    // `AgentKeysScope.getScope` so the permission panel reflects the REAL grant
    // (`None` for no/empty grant → the panel's DENY is then chain-accurate).
    // Best-effort per agent; a read failure leaves that row's scope untouched.
    if let Some(scope_contract) = scope_contract_address(state) {
        // #404: registry-derived reverse map (keccak(channel-pub/sub:<id>) →
        // name) so channel grants re-NAME after a daemon restart — this is what
        // keeps device detection + channel chips durable across restarts.
        // Best-effort: an unreachable registry only skips the naming.
        let channel_candidates = match ensure_channel_registry(state).await {
            Ok(reg) => channel_service_candidates(&reg),
            Err(e) => {
                tracing::debug!(
                    target: "agentkeys.daemon.ui_bridge",
                    "channel registry unavailable for scope naming: {e}"
                );
                HashMap::new()
            }
        };
        let agent_rows: Vec<(String, String)> = state
            .actors
            .read()
            .await
            .values()
            .filter(|a| a.role == "agent")
            .map(|a| (a.id.clone(), a.omni_hex.clone()))
            .collect();
        for (id, actor_omni) in agent_rows {
            match fetch_actor_scope_from_chain(&rpc, &scope_contract, &omni, &actor_omni).await {
                Ok((scope, unknown_ids)) => {
                    // Registry match — names recovered from hashes. unknown_ids
                    // stays UNCHANGED (the #248 preserve semantics: a memory
                    // commit must keep echoing every non-memory hash).
                    let matched: Vec<String> = unknown_ids
                        .iter()
                        .filter_map(|h| channel_candidates.get(&h.to_lowercase()).cloned())
                        .collect();
                    if let Some(a) = state.actors.write().await.get_mut(&id) {
                        a.scope = scope;
                        a.scope_unknown_service_ids =
                            (!unknown_ids.is_empty()).then_some(unknown_ids);
                        if !matched.is_empty() {
                            let services = a.services.get_or_insert_with(Vec::new);
                            for name in matched {
                                if !services.iter().any(|s| s.eq_ignore_ascii_case(&name)) {
                                    services.push(name);
                                }
                            }
                        }
                        // #424 §1 — manifest self-heal for rows that predate the
                        // manifest fetch in this process (placeholder rows from
                        // an earlier reconcile): fill missing service NAMES +
                        // the device kind; never overwrite live pairing data.
                        if let Some(e) = manifest.as_ref().and_then(|m| {
                            m.entry_for(&actor_omni, a.device_key_hash.as_deref().unwrap_or(""))
                        }) {
                            if a.services.as_deref().unwrap_or_default().is_empty()
                                && !e.granted_service_names.is_empty()
                            {
                                a.services = Some(e.granted_service_names.clone());
                            }
                            if e.kind == "device" && a.vendor.is_empty() {
                                a.vendor = "device".into();
                                a.device = "channel-endpoint device (§10.2)".into();
                            }
                        }
                    }
                }
                Err(e) => tracing::debug!(
                    target: "agentkeys.daemon.ui_bridge",
                    "scope read for {id} failed: {e}"
                ),
            }
        }
    }
    Ok(added)
}

/// Invalidate the lazy #233 actor-tree sync: bump the fleet generation so the
/// next `/v1/actors` read reconciles from chain. Call after ANY fleet mutation
/// (master register, device add/revoke, scope change, reset). Race-safe: a
/// reconcile already in flight when this fires only marks itself synced up to
/// the OLDER generation it observed, so this newer invalidation still forces a
/// re-sync (the empty-actor-page TOCTOU fix).
fn invalidate_fleet_sync(state: &UiBridgeState) {
    state
        .fleet_gen
        .fetch_add(1, std::sync::atomic::Ordering::Release);
}

/// Record that the master is now bound on chain AND invalidate the actor-tree
/// sync (#233). EVERY path that learns the master is registered routes through
/// here — register-submit (both transports), the already-bound idempotent
/// skips, restart rehydrate, and re-login — so a latch poisoned by an earlier
/// EMPTY reconcile can never leave `/v1/actors` permanently empty after the
/// master registers (Codex adversarial-review finding: centralize the
/// "master is now known registered" transition).
async fn mark_master_registered(state: &UiBridgeState, registered: RegisteredMaster) {
    *state.registered_master.write().await = Some(registered);
    invalidate_fleet_sync(state);
}

/// #435 — `GET /v1/master/register/state`: the ON-CHAIN truth for "does this
/// operator already have a bound master?", read fresh (never the session
/// cache). Onboarding calls this BEFORE `navigator.credentials.create`:
/// - `bound` + `probe:"chain"` → SKIP enroll+register (rehydrate/re-auth the
///   existing passkey instead — a fresh passkey here would strand the browser
///   on a key the registry doesn't hold).
/// - unbound + `probe:"chain"` → the register ceremony is safe to run
///   (first-master-only hasn't fired; a replacement passkey is harmless).
/// - `probe:"unconfigured"|"error"` → the chain could not answer; the app must
///   NOT auto-mint (fail-safe) — retry or proceed only on explicit user intent.
#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiRegisterState {
    pub operator_omni: String,
    pub bound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub master_account: Option<String>,
    /// `"chain"` (fresh read) · `"unconfigured"` (no RPC/registry on this
    /// daemon — dev/no-infra) · `"error"` (read failed; see `probe_error`).
    pub probe: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub probe_error: Option<String>,
}

async fn master_register_state(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    let Some(omni) = held_operator_omni(&state).await else {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "no master session — verify email first (the probe is omni-keyed)"
            })),
        )
            .into_response();
    };
    let omni = normalize_omni_0x(&omni).to_lowercase();
    let rpc = state.chain_profile.rpc.http.clone();
    let view = match registry_address(&state) {
        Some(registry) if !rpc.is_empty() => {
            match probe_operator_master_wallet(&rpc, &registry, &omni).await {
                Ok(Some(account)) => {
                    // Idempotent bookkeeping: the chain says bound — mirror it
                    // so onboarding-state + cap-mint resolve without a fresh
                    // register (the #220 rehydrate posture).
                    if let Ok(dkh) = agentkeys_core::device_crypto::device_key_hash_from_omni(&omni)
                    {
                        mark_master_registered(
                            &state,
                            RegisteredMaster {
                                device_key_hash: dkh,
                                operator_omni: omni.clone(),
                                tx_hash: None,
                                account: Some(account.clone()),
                            },
                        )
                        .await;
                    }
                    ApiRegisterState {
                        operator_omni: omni,
                        bound: true,
                        master_account: Some(account),
                        probe: "chain".into(),
                        probe_error: None,
                    }
                }
                Ok(None) => ApiRegisterState {
                    operator_omni: omni,
                    bound: false,
                    master_account: None,
                    probe: "chain".into(),
                    probe_error: None,
                },
                Err(e) => ApiRegisterState {
                    operator_omni: omni,
                    bound: false,
                    master_account: None,
                    probe: "error".into(),
                    probe_error: Some(e),
                },
            }
        }
        _ => ApiRegisterState {
            operator_omni: omni,
            bound: false,
            master_account: None,
            probe: "unconfigured".into(),
            probe_error: None,
        },
    };
    Json(view).into_response()
}

/// Lazy #233 sync gate for the read paths: reconstruct the actor tree from chain
/// whenever the in-memory map is older than the latest fleet invalidation.
/// Serialized by `fleet_sync_lock` so concurrent `/v1/actors` reads don't each
/// hit the chain. Errors are logged + retried on the next call (RPC may be
/// down). Crucially, a reconcile only advances `fleet_synced_gen` to the
/// generation it OBSERVED before the chain read — so an invalidation that races
/// the read still forces a re-sync (the TOCTOU fix: a stale EMPTY reconcile can
/// no longer latch "synced" over a master-register that landed mid-read).
async fn maybe_sync_fleet_from_chain(state: &SharedUiBridgeState) {
    use std::sync::atomic::Ordering;
    // Fast path: the in-memory map already reflects the latest invalidation.
    if state.fleet_synced_gen.load(Ordering::Acquire) >= state.fleet_gen.load(Ordering::Acquire) {
        return;
    }
    if held_operator_omni(state).await.is_none() {
        return; // nobody onboarded — nothing to reconstruct (do NOT advance the synced gen)
    }
    let _lock = state.fleet_sync_lock.lock().await;
    // Re-check under the lock — another task may have synced while we waited —
    // and capture the generation we're reconciling against AFTER acquiring it,
    // so we never claim to be synced past an invalidation we didn't observe.
    let target = state.fleet_gen.load(Ordering::Acquire);
    if state.fleet_synced_gen.load(Ordering::Acquire) >= target {
        return;
    }
    match reconcile_actors_from_chain(state).await {
        Ok(added) => {
            // Advance ONLY to the observed generation. If an invalidation bumped
            // fleet_gen during the chain reads, fleet_synced_gen stays below it
            // and the next read re-reconciles — a stale empty read can't mask it.
            state.fleet_synced_gen.fetch_max(target, Ordering::Release);
            if added > 0 {
                tracing::info!(
                    target: "agentkeys.daemon.ui_bridge",
                    added,
                    "#233: actor tree reconstructed from chain"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                "#233: chain fleet reconstruction failed (will retry on next read): {e}"
            );
        }
    }
}

async fn list_actors(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    // #233: post-restart the in-memory map is empty while the chain still holds
    // the fleet — reconstruct lazily before serving.
    maybe_sync_fleet_from_chain(&state).await;
    let guard = state.actors.read().await;
    let mut actors: Vec<ApiActor> = guard.values().cloned().collect();
    drop(guard);
    // Stable order: master first, then by id.
    actors.sort_by(|a, b| {
        let a_master = if a.role == "master" { 0 } else { 1 };
        let b_master = if b.role == "master" { 0 } else { 1 };
        a_master.cmp(&b_master).then_with(|| a.id.cmp(&b.id))
    });
    let master_account = master_account_address(&state).await;
    let actors: Vec<ApiActor> = actors
        .iter()
        .map(|a| enrich_actor_account(a, master_account.as_deref()))
        .collect();
    Json(serde_json::json!({ "actors": actors }))
}

async fn get_actor(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let actor = {
        let guard = state.actors.read().await;
        guard.get(&id).cloned()
    }
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let master_account = master_account_address(&state).await;
    let enriched = enrich_actor_account(&actor, master_account.as_deref());
    Ok(Json(
        serde_json::to_value(&enriched).unwrap_or_else(|_| serde_json::json!({})),
    ))
}

/// The master's on-chain P256Account (`operatorMasterWallet[omni]`). Prefers
/// the in-memory register record; when a RESTORED session lost it, backfills
/// live from the registry and caches — a stale `None` here made the actor page
/// claim "not yet bound" AND sent the unpair down the doomed EOA script path
/// while the master WAS a bound P256Account (real 2026-06-11 incident).
async fn master_account_address(state: &SharedUiBridgeState) -> Option<String> {
    if let Some(acc) = state
        .registered_master
        .read()
        .await
        .as_ref()
        .and_then(|m| m.account.clone())
    {
        return Some(acc);
    }
    let omni = held_operator_omni(state).await?;
    let registry = registry_address(state)?;
    let rpc = state.chain_profile.rpc.http.clone();
    let acc = fetch_operator_master_wallet(&rpc, &registry, &omni).await?;
    if let Some(rm) = state.registered_master.write().await.as_mut() {
        if rm.account.is_none() {
            rm.account = Some(acc.clone());
        }
    }
    Some(acc)
}

/// `operatorMasterWallet[omni]` — `None` when unset (zero address) or the read
/// fails. Shared by the #233 reconcile backfill and the live actor-page read.
async fn fetch_operator_master_wallet(rpc: &str, registry: &str, omni_0x: &str) -> Option<String> {
    probe_operator_master_wallet(rpc, registry, omni_0x)
        .await
        .ok()
        .flatten()
}

/// #435 — the register-probe variant: distinguishes UNBOUND (`Ok(None)`) from
/// a FAILED read (`Err`). The onboarding register-or-skip decision must never
/// treat an RPC hiccup as "unbound" — minting a fresh passkey for an omni
/// whose chain binding simply couldn't be read would strand the browser on a
/// key the registry doesn't hold (every later ceremony SIG_VALIDATION-fails).
async fn probe_operator_master_wallet(
    rpc: &str,
    registry: &str,
    omni_0x: &str,
) -> Result<Option<String>, String> {
    let omni_bare = omni_0x.trim_start_matches("0x").to_lowercase();
    let data = format!(
        "0x{}{omni_bare}",
        chain_selector("operatorMasterWallet(bytes32)")
    );
    let raw = daemon_eth_call(rpc, registry, &data).await?;
    if raw.len() < 32 {
        return Err(format!(
            "operatorMasterWallet short return ({} bytes)",
            raw.len()
        ));
    }
    if raw[12..32].iter().any(|b| *b != 0) {
        Ok(Some(format!("0x{}", hex::encode(&raw[12..32]))))
    } else {
        Ok(None)
    }
}

/// #225 / E7: attach the actor's on-chain account address + type to its serialized
/// JSON for the actor page. master → its passkey **P256Account** (the smart account
/// that holds master authority); agents → their K10 **device** identity. The
/// `account_type` lets the UI distinguish a bound smart-account master (`p256account`)
/// from an unbound one (`none` → "register on chain" CTA).
fn enrich_actor_account(a: &ApiActor, master_account: Option<&str>) -> ApiActor {
    let (addr, ty): (Option<String>, &str) = if a.role == "master" {
        match master_account {
            Some(acc) => (Some(acc.to_string()), "p256account"),
            None => (None, "none"),
        }
    } else {
        // Agents are K10 devices (not ERC-4337 accounts) — surface the omni identity.
        (Some(a.omni_hex.clone()), "device")
    };
    let mut out = a.clone();
    out.account_address = addr;
    out.account_type = Some(ty.to_string());
    out
}

async fn list_caps(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let guard = state.caps.read().await;
    let caps = guard.get(&id).cloned().unwrap_or_default();
    Json(serde_json::json!({ "caps": caps }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateScopeRequest {
    pub namespace: String,
    pub read: bool,
    pub write: bool,
}

/// `POST /v1/actors/:id/scope` — a LOCAL-VIEW write only (daemon map + audit
/// row); it never touches chain, and the #233 mirror overwrites it on the next
/// `list_actors`. The REAL on-chain commit is the #248 Touch-ID flow
/// (`/v1/scope/build` + `/v1/scope/submit`), which the permissions panel drives.
async fn update_scope(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateScopeRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let scope = actor.scope.get_or_insert_with(HashMap::new);
    scope.insert(
        req.namespace.clone(),
        ApiScopeBits {
            read: req.read,
            write: req.write,
        },
    );
    let snapshot = actor.clone();
    drop(guard);

    let evt = ApiAuditEvent {
        id: format!("e-scope-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "scope.updated".into(),
        detail: format!(
            "{} · {} · read={} write={}",
            id, req.namespace, req.read, req.write
        ),
        chip: "broker".into(),
        sev: "ok".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct GrantScopeRequest {
    pub data_class: String,
    /// The namespace (memory) or service id (credentials) being granted.
    pub entity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub gating: String,
}

/// `POST /v1/actors/:id/scope/grant` (#207 items 5/7/8) — record a CONFIRMED
/// auto-distribute grant: a memory namespace the agent inherits (read) or a
/// credential service it may use. Same daemon-state + audit posture as
/// `update_scope` — a scope VIEW write; the on-chain `setScope` paths are the
/// #248 web Touch-ID flow (`/v1/scope/{build,submit}`) and the operator CLI
/// `heima-scope-set.sh` (a master `SCOPE_MGMT` + K11 mutation). Wiring the
/// auto-distribute confirm into the #248 flow is a follow-up; until then the
/// #233 mirror overwrites this view on the next `list_actors`.
///
/// A `Sensitive` grant only reaches this endpoint after an explicit per-grant K11
/// confirm in the UI; a `Safe` one after the reviewed-set confirm. `propose` never
/// calls this — so an unconfirmed sensitive category is never granted (the §3.2
/// invariant, enforced end to end).
async fn grant_service_scope(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<GrantScopeRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let (chip, label) = if req.data_class == "memory" {
        // Memory inheritance (#207 item 8): granting a namespace = read access.
        let scope = actor.scope.get_or_insert_with(HashMap::new);
        scope.insert(
            req.entity.clone(),
            ApiScopeBits {
                read: true,
                write: false,
            },
        );
        ("memory", format!("memory:{}", req.entity))
    } else {
        // Credential grant (#207 item 7): the service joins the agent's services.
        let services = actor.services.get_or_insert_with(Vec::new);
        if !services.contains(&req.entity) {
            services.push(req.entity.clone());
        }
        ("creds", req.entity.clone())
    };
    let snapshot = actor.clone();
    drop(guard);

    let how = if req.gating == "k11" {
        "K11-confirmed"
    } else {
        "auto-confirmed"
    };
    let detail = if req.category.is_empty() {
        format!("granted {label} · {how} · chain commit via master K11")
    } else {
        format!(
            "granted {label} · {} · {how} · chain commit via master K11",
            req.category
        )
    };
    let evt = ApiAuditEvent {
        id: format!("e-grant-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: id.clone(),
        actor: id.clone(),
        kind: "scope.granted".into(),
        detail,
        chip: chip.into(),
        sev: "ok".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePaymentCapRequest {
    pub per_tx: f64,
    pub daily: f64,
}

async fn update_payment_cap(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePaymentCapRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    let mut guard = state.actors.write().await;
    let actor = guard
        .get_mut(&id)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
    let cap = actor.payment_cap.get_or_insert(ApiPaymentCap {
        per_tx: 0.0,
        daily: 0.0,
        currency: "USDC".into(),
    });
    cap.per_tx = req.per_tx;
    cap.daily = req.daily;
    let snapshot = actor.clone();
    drop(guard);

    let evt = ApiAuditEvent {
        id: format!("e-paycap-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "payment-cap.updated".into(),
        detail: format!("{} · per_tx={} daily={}", id, req.per_tx, req.daily),
        chip: "broker".into(),
        sev: "ok".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct RevokeDeviceRequest {
    pub intent_text: String,
    pub intent_fields: Vec<(String, String)>,
    /// `true` ⇒ the browser already landed `revokeAgentDevice` ON CHAIN via the
    /// Touch-ID UserOp (`/v1/revoke/{build,submit}`); the daemon VERIFIES the
    /// device entry reads `revoked` from the registry and only then flips local
    /// state — no script shell-out. `false` (default) ⇒ legacy script path
    /// (works only when `operatorMasterWallet` is the script's EOA).
    #[serde(default)]
    pub onchain: bool,
    /// The submit's tx hash (audit trail only; the chain re-read is the proof).
    #[serde(default)]
    pub onchain_tx_hash: Option<String>,
    /// #97: the `AuditEnvelope v1` receipt hashes from the broker's
    /// `/v1/revoke/submit` response — attached to the feed event so the decode
    /// view fetches the REAL DeviceRevoke envelope instead of synthesizing.
    #[serde(default)]
    pub audit_envelope_hashes: Option<Vec<String>>,
}

async fn revoke_device(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<RevokeDeviceRequest>,
) -> Result<Json<ApiActor>, (StatusCode, Json<ErrorBody>)> {
    // Read the actor's on-chain device key hash + label first. The revoke must land
    // ON CHAIN before we flip local state — a binding is not gone until
    // SidecarRegistry.revokeAgentDevice says so (the "also need on-chain" rule).
    let (label, device_key_hash) = {
        let guard = state.actors.read().await;
        let actor = guard
            .get(&id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
        (actor.label.clone(), actor.device_key_hash.clone())
    };

    let tx = if req.onchain {
        // The browser already executed revokeAgentDevice as the master-account
        // Touch-ID UserOp (/v1/revoke/{build,submit}) — the only signer the
        // registry accepts for an account-master operator. Don't trust the
        // client: re-read the device entry and require `revoked` before
        // flipping local state.
        let hash = device_key_hash.clone().ok_or_else(|| {
            err(
                StatusCode::CONFLICT,
                "actor has no on-chain device_key_hash to verify the revoke against",
                "device-hash-missing",
            )
        })?;
        let registry = registry_address(&state).ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "chain profile carries no SidecarRegistry — cannot verify the revoke",
                "chain-unconfigured",
            )
        })?;
        let rpc = state.chain_profile.rpc.http.clone();
        let bare = hash.trim_start_matches("0x").to_lowercase();
        let hash32: [u8; 32] = hex::decode(&bare)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                err(
                    StatusCode::CONFLICT,
                    "actor device_key_hash is not 32-byte hex",
                    "device-hash-malformed",
                )
            })?;
        let data = format!("0x{}{bare}", chain_selector("getDevice(bytes32)"));
        let raw = daemon_eth_call(&rpc, &registry, &data).await.map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("revoke verify read failed: {e}"),
                "revoke-verify-failed",
            )
        })?;
        let entry = parse_device_entry(&raw, &hash32).map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("revoke verify parse failed: {e}"),
                "revoke-verify-failed",
            )
        })?;
        if !entry.revoked {
            return Err(err(
                StatusCode::CONFLICT,
                "chain says the device is still active — the revoke UserOp did not land",
                "revoke-not-onchain",
            ));
        }
        req.onchain_tx_hash.clone()
    } else {
        // Legacy script path (heima-device-revoke.sh, EOA-signed) — works only
        // when operatorMasterWallet IS the script's EOA (pre-#225 operators).
        let master_script = state.register_master_script.clone().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "chain not configured (no --register-master-script) — cannot revoke on chain",
                "chain-unconfigured",
            )
        })?;
        let revoke_script =
            resolve_repo_script(&master_script, "heima-device-revoke.sh").ok_or_else(|| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "heima-device-revoke.sh not found (looked next to --register-master-script and in <repo>/scripts/)",
                    "revoke-script-missing",
                )
            })?;
        // Prefer the on-chain device key hash — it works for chain-reconstructed
        // actors (#233) that never had a ~/.agentkeys/agents/<label>.json record
        // on this machine (the label-file path died with "no agent file" — real
        // 2026-06-11 unpair incident). Label fallback covers legacy rows only.
        // Same selection as the #243 master-reset fleet teardown.
        match &device_key_hash {
            Some(hash) => revoke_agent_device_by_hash(&revoke_script, hash).await,
            None => revoke_agent_device(&revoke_script, &label).await,
        }
        .map_err(|e| {
            err(
                StatusCode::BAD_GATEWAY,
                format!("on-chain revoke failed: {e}"),
                "revoke-onchain-failed",
            )
        })?
    };

    // On-chain revoke landed (or idempotent-skip) → flip local state + drop caps.
    let snapshot = {
        let mut guard = state.actors.write().await;
        let actor = guard
            .get_mut(&id)
            .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such actor", "actor-not-found"))?;
        actor.status = "bad".into();
        actor.last_active = "revoked".into();
        if !actor.label.ends_with(" (revoked)") {
            actor.label.push_str(" (revoked)");
        }
        actor.clone()
    };

    // Invalidate every cap minted for this actor (TTL → 0).
    state.caps.write().await.remove(&id);

    let evt = ApiAuditEvent {
        id: format!("e-revoke-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "device.revoked".into(),
        detail: format!(
            "{} · on-chain revokeAgentDevice{} · intent='{}' · fields={}",
            id,
            tx.as_deref()
                .map(|h| format!(" tx={h}"))
                .unwrap_or_default(),
            req.intent_text,
            req.intent_fields.len()
        ),
        chip: "revoke".into(),
        sev: "bad".into(),
        // #97: real coordinates from the Touch-ID revoke submit — the decode
        // view fetches the DeviceRevoke envelope by hash when present.
        tx_hash: tx.clone(),
        audit_envelope_hashes: req.audit_envelope_hashes.clone().filter(|h| !h.is_empty()),
    };
    push_audit(&state, evt).await;
    Ok(Json(snapshot))
}

#[derive(Debug, Deserialize)]
pub struct RevokeCapRequest {
    pub cap: String,
    pub intent_text: String,
}

async fn revoke_cap(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<RevokeCapRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    {
        let actors = state.actors.read().await;
        if !actors.contains_key(&id) {
            return Err(err(
                StatusCode::NOT_FOUND,
                "no such actor",
                "actor-not-found",
            ));
        }
    }
    let mut caps_guard = state.caps.write().await;
    if let Some(caps) = caps_guard.get_mut(&id) {
        caps.retain(|c| c.cap != req.cap);
    }
    drop(caps_guard);

    let evt = ApiAuditEvent {
        id: format!("e-cap-revoke-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "cap.revoked".into(),
        detail: format!("{} · cap={} · intent='{}'", id, req.cap, req.intent_text),
        chip: "revoke".into(),
        sev: "bad".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(&state, evt).await;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
pub struct ListRecentAuditQuery {
    #[serde(default)]
    pub actor_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

async fn list_recent_audit(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<ListRecentAuditQuery>,
) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(AUDIT_BUFFER_CAP);
    let guard = state.audit.read().await;
    let mut events: Vec<ApiAuditEvent> = guard
        .iter()
        .rev()
        .filter(|e| q.actor_id.as_deref().is_none_or(|a| e.actor_id == a))
        .take(limit)
        .cloned()
        .collect();
    // Reverse-rev: newest first, which is the natural iteration order
    // when we push_back + iter().rev(). Already in that order; ensure stable.
    // (Re-sort by ts descending as a safety belt for ties.)
    events.sort_by(|a, b| b.ts.cmp(&a.ts));
    Json(serde_json::json!({ "events": events }))
}

async fn audit_stream(
    State(state): State<SharedUiBridgeState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.audit_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(evt) => match serde_json::to_string(&evt) {
            Ok(json) => Some(Ok(Event::default().event("audit").data(json))),
            Err(_) => None,
        },
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn anchor_status(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let mut snapshot = state.anchor.read().await.clone();
    // Compute next_anchor_in dynamically (2-min cadence per arch.md §11).
    let now = now_unix();
    if snapshot.last_anchor_at > 0 {
        let elapsed = now.saturating_sub(snapshot.last_anchor_at);
        snapshot.next_anchor_in = 120u64.saturating_sub(elapsed % 120);
    } else {
        snapshot.next_anchor_in = 120u64.saturating_sub(now % 120);
    }
    Json(snapshot)
}

/// A chain is SUPPORTED (listable + viewable in the web switcher) iff its
/// profile records a deployed AgentKeys contract set. Data-driven on purpose
/// (no hardcoded chain list): today that is exactly heima + base mainnet;
/// a future chain joins the moment its bring-up writes `contracts[]` +
/// `contract_set_version` into its profile.
fn profile_is_supported(p: &agentkeys_core::chain_profile::ChainProfile) -> bool {
    !p.contracts.is_empty() && p.contract_set_version.is_some()
}

/// The chain RPC the daemon should dial, read from `AGENTKEYS_CHAIN_RPC_HTTP[_<CHAIN>]`
/// — the SAME env var the broker (`accept.rs`/`cap.rs`), every worker (`state.rs`) and
/// the bundler (`main.rs`) already read. The daemon was the ONE component that sourced
/// its RPC from the compiled chain profile instead, so a deployed env never reached it;
/// reading the same var here removes that divergence. `<CHAIN>` is the upper-cased
/// profile name (`-`→`_`), with bare `AGENTKEYS_CHAIN_RPC_HTTP` as the fallback. Unset /
/// blank ⇒ `None` (caller keeps the profile default). Pure (lookup injected) so it's
/// testable without mutating process env (#258).
fn chain_rpc_from_env(chain_name: &str, lookup: impl Fn(&str) -> Option<String>) -> Option<String> {
    let suffix = chain_name.to_uppercase().replace('-', "_");
    lookup(&format!("AGENTKEYS_CHAIN_RPC_HTTP_{suffix}"))
        .or_else(|| lookup("AGENTKEYS_CHAIN_RPC_HTTP"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve which profile `GET /v1/chain/info` serves: the daemon's
/// operational profile by default, or any SUPPORTED built-in profile when
/// the UI asks for a different view chain via `?chain=` (#282 web chain
/// switcher). This is a stateless VIEW selection — the daemon's operational
/// chain (RPC reads, onboarding state, ceremonies, broker coordinates)
/// never changes, and the daemon's own chain is always viewable even if its
/// profile carries no registry (dev chains like anvil).
fn resolve_view_profile(
    daemon_profile: &agentkeys_core::chain_profile::ChainProfile,
    requested: Option<&str>,
) -> Result<agentkeys_core::chain_profile::ChainProfile, String> {
    match requested.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(daemon_profile.clone()),
        Some(name) if name.eq_ignore_ascii_case(&daemon_profile.name) => Ok(daemon_profile.clone()),
        Some(name) => {
            let p = agentkeys_core::chain_profile::ChainProfile::load_builtin(name)
                .map_err(|e| e.to_string())?;
            if !profile_is_supported(&p) {
                return Err(format!(
                    "chain '{name}' has no deployed AgentKeys contract set — supported chains are listed by /v1/chain/list"
                ));
            }
            Ok(p)
        }
    }
}

#[cfg(test)]
mod chain_view_tests {
    use super::resolve_view_profile;
    use agentkeys_core::chain_profile::ChainProfile;

    #[test]
    fn default_serves_the_daemon_profile() {
        let daemon = ChainProfile::load_builtin("heima").unwrap();
        let p = resolve_view_profile(&daemon, None).unwrap();
        assert_eq!(p.name, "heima");
        let p = resolve_view_profile(&daemon, Some("")).unwrap();
        assert_eq!(p.name, "heima");
    }

    #[test]
    fn view_chain_serves_any_builtin_without_touching_daemon_profile() {
        let daemon = ChainProfile::load_builtin("heima").unwrap();
        let p = resolve_view_profile(&daemon, Some("base")).unwrap();
        assert_eq!(p.chain_id, 8453);
        assert_eq!(daemon.name, "heima");
    }

    #[test]
    fn same_name_is_case_insensitive_and_keeps_the_daemon_copy() {
        let daemon = ChainProfile::load_builtin("heima").unwrap();
        let p = resolve_view_profile(&daemon, Some("HEIMA")).unwrap();
        assert_eq!(p.chain_id, daemon.chain_id);
    }

    #[test]
    fn unknown_chain_is_an_error_naming_the_builtins() {
        let daemon = ChainProfile::load_builtin("heima").unwrap();
        let e = resolve_view_profile(&daemon, Some("doesnotexist")).unwrap_err();
        assert!(e.contains("doesnotexist"));
        assert!(e.contains("heima"));
    }

    #[test]
    fn chain_rpc_from_env_matches_broker_precedence() {
        use super::chain_rpc_from_env;
        use std::collections::HashMap;
        // chain-suffixed wins — the same var the broker/workers/bundler read.
        let base: HashMap<&str, &str> = [(
            "AGENTKEYS_CHAIN_RPC_HTTP_BASE",
            "https://base-rpc.publicnode.com",
        )]
        .into();
        assert_eq!(
            chain_rpc_from_env("base", |k| base.get(k).map(|v| v.to_string())),
            Some("https://base-rpc.publicnode.com".into())
        );
        // bare var is the fallback when no chain-suffixed override is set.
        let bare: HashMap<&str, &str> = [("AGENTKEYS_CHAIN_RPC_HTTP", "https://x")].into();
        assert_eq!(
            chain_rpc_from_env("heima", |k| bare.get(k).map(|v| v.to_string())),
            Some("https://x".into())
        );
        // unset ⇒ None (caller keeps the profile default); blank ⇒ None.
        assert_eq!(chain_rpc_from_env("base", |_| None), None);
        assert_eq!(chain_rpc_from_env("base", |_| Some("  ".into())), None);
    }

    #[test]
    fn builtin_without_a_deployed_registry_is_not_viewable() {
        // ethereum/sepolia/anvil ship as profiles but carry no AgentKeys
        // contract set — the switcher must not offer or serve them.
        let daemon = ChainProfile::load_builtin("heima").unwrap();
        let e = resolve_view_profile(&daemon, Some("ethereum")).unwrap_err();
        assert!(e.contains("no deployed AgentKeys contract set"));
    }

    #[test]
    fn the_daemon_own_chain_is_always_viewable_even_without_a_registry() {
        // A dev daemon on anvil must still see its own chain page.
        let daemon = ChainProfile::load_builtin("anvil").unwrap();
        let p = resolve_view_profile(&daemon, Some("anvil")).unwrap();
        assert_eq!(p.name, "anvil");
    }
}

#[cfg(test)]
mod stack_list_tests {
    use super::{parse_stacks_json, stack_is_active, StackEntry};

    fn entry(name: &str, chain: &str, broker: &str) -> StackEntry {
        StackEntry {
            name: name.into(),
            chain: chain.into(),
            broker_url: broker.into(),
        }
    }

    #[test]
    fn parses_the_fleet_injected_inventory() {
        let raw = r#"[
            {"name":"prod","chain":"heima","broker_url":"https://broker.litentry.org"},
            {"name":"base","chain":"base","broker_url":"https://broker-base.litentry.org"},
            {"name":"ve","chain":"heima","broker_url":"https://broker.agentterrier.cn"}
        ]"#;
        let stacks = parse_stacks_json(Some(raw));
        assert_eq!(stacks.len(), 3);
        assert_eq!(
            stacks[2],
            entry("ve", "heima", "https://broker.agentterrier.cn")
        );
    }

    #[test]
    fn unset_blank_or_malformed_yields_empty() {
        assert!(parse_stacks_json(None).is_empty());
        assert!(parse_stacks_json(Some("   ")).is_empty());
        assert!(parse_stacks_json(Some("not json")).is_empty());
        // half-valid list fails whole (never silently drop one stack)
        assert!(parse_stacks_json(Some(r#"[{"name":"x"}]"#)).is_empty());
    }

    // The #373 isolation invariant at the selector layer: the SAME chain via a
    // DIFFERENT broker is NOT the active stack — a Heima-VE daemon must never
    // mark (or be marked as) the Heima-AWS stack, and vice versa.
    #[test]
    fn same_chain_different_broker_is_not_active() {
        let aws = entry("prod", "heima", "https://broker.litentry.org");
        let ve = entry("ve", "heima", "https://broker.agentterrier.cn");
        // daemon bound to the AWS broker:
        assert!(stack_is_active(
            &aws,
            "heima",
            Some("https://broker.litentry.org")
        ));
        assert!(!stack_is_active(
            &ve,
            "heima",
            Some("https://broker.litentry.org")
        ));
        // daemon bound to the VE broker:
        assert!(stack_is_active(
            &ve,
            "heima",
            Some("https://broker.agentterrier.cn")
        ));
        assert!(!stack_is_active(
            &aws,
            "heima",
            Some("https://broker.agentterrier.cn")
        ));
    }

    #[test]
    fn active_matching_normalizes_case_and_trailing_slash() {
        let ve = entry("ve", "heima", "https://broker.agentterrier.cn");
        assert!(stack_is_active(
            &ve,
            "HEIMA",
            Some("https://broker.agentterrier.cn/")
        ));
        // a brokerless daemon matches no inventory stack
        assert!(!stack_is_active(&ve, "heima", None));
        // a different chain on the same broker URL is not active either
        assert!(!stack_is_active(
            &ve,
            "base",
            Some("https://broker.agentterrier.cn")
        ));
    }
}

#[derive(serde::Deserialize)]
struct ChainInfoQuery {
    chain: Option<String>,
}

/// `GET /v1/chain/info[?chain=<name>]` — a chain's deployed contract registry
/// for the parent-control chain page (#153). With no query: the chain the
/// daemon operates on. With `?chain=`: any built-in profile (the #282 web
/// chain switcher — view-only; `daemonChain` always names the operational
/// chain so the UI can label the difference).
async fn chain_info(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<ChainInfoQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let p = resolve_view_profile(&state.chain_profile, q.chain.as_deref())
        .map_err(|e| err(StatusCode::BAD_REQUEST, &e, "unknown-chain"))?;
    let contracts: Vec<serde_json::Value> = p
        .contracts
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "address": c.address,
                "purpose": c.purpose,
                "deployedAt": c.deployed_at,
                "explorerUrl": p.explorer.contract_url(&c.address),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "name": p.name,
        "display": p.display_name,
        "chainId": p.chain_id,
        "rpc": p.rpc.http,
        "wss": p.rpc.wss,
        "explorer": p.explorer.url,
        "tokenSymbol": p.token.symbol,
        "tokenDecimals": p.token.decimals,
        "finality": p.finality.default_block_tag,
        "contracts": contracts,
        "daemonChain": state.chain_profile.name,
        "daemonBroker": state.broker_url,
    })))
}

/// One (chain, broker) pair of the operator's stack inventory (#373 — the
/// stack axis gained a cloud dimension: the SAME chain can be served by
/// different brokers/data planes, e.g. Heima-AWS vs Heima-VE). Parsed from
/// `AGENTKEYS_STACKS_JSON`; field names are the env-file / fleet spellings.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct StackEntry {
    pub name: String,
    pub chain: String,
    pub broker_url: String,
}

/// Parse `AGENTKEYS_STACKS_JSON` (`[{"name","chain","broker_url"}]`). Unset /
/// blank ⇒ empty (the endpoint then synthesizes the daemon's own stack); a
/// MALFORMED value warns loudly and yields empty rather than half a list —
/// a silently-dropped stack would read as "that broker doesn't exist".
fn parse_stacks_json(raw: Option<&str>) -> Vec<StackEntry> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<StackEntry>>(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "ui-bridge: AGENTKEYS_STACKS_JSON is malformed — /v1/stack/list will only show the daemon's own stack");
            Vec::new()
        }
    }
}

/// Whether an inventory stack IS the stack this daemon runs: same chain
/// (case-insensitive) and same broker URL (trailing-slash-insensitive). The
/// broker comparison is what splits Heima-AWS from Heima-VE — chain alone
/// can't (#373).
fn stack_is_active(entry: &StackEntry, daemon_chain: &str, daemon_broker: Option<&str>) -> bool {
    let norm = |u: &str| u.trim_end_matches('/').to_ascii_lowercase();
    entry.chain.eq_ignore_ascii_case(daemon_chain)
        && daemon_broker.map(norm) == Some(norm(&entry.broker_url))
}

/// `GET /v1/stack/list` — the operator's stack inventory for the web stack
/// selector (#373): every known (chain, broker) pair, which one this daemon
/// runs (`active`), and a live per-broker `/healthz` probe (`healthy`) so an
/// unbootable stack (the VE broker until its runtime-port follow-ups land)
/// renders degraded instead of selectable. Selecting a DIFFERENT stack is not
/// a web action — the daemon binds one (chain, broker) per boot (relaunch via
/// the fleet `c` picker / dev.sh env); that per-boot binding is exactly the
/// isolation guarantee that a Heima-VE session never talks to the AWS broker.
async fn stack_list(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    let daemon_chain = state.chain_profile.name.clone();
    let mut stacks = state.stacks.clone();
    if stacks.is_empty() {
        if let Some(broker) = &state.broker_url {
            stacks.push(StackEntry {
                name: daemon_chain.clone(),
                chain: daemon_chain.clone(),
                broker_url: broker.clone(),
            });
        }
    }
    let probes = stacks.iter().map(|s| {
        let url = format!("{}/healthz", s.broker_url.trim_end_matches('/'));
        async move {
            let ok = reqwest::Client::new()
                .get(&url)
                .timeout(std::time::Duration::from_secs(3))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            ok
        }
    });
    let healthy = futures_util::future::join_all(probes).await;
    let rows: Vec<serde_json::Value> = stacks
        .iter()
        .zip(healthy)
        .map(|(s, ok)| {
            serde_json::json!({
                "name": s.name,
                "chain": s.chain,
                "brokerUrl": s.broker_url,
                "active": stack_is_active(s, &daemon_chain, state.broker_url.as_deref()),
                "healthy": ok,
            })
        })
        .collect();
    Json(serde_json::json!({
        "stacks": rows,
        "daemonChain": daemon_chain,
        "daemonBroker": state.broker_url,
    }))
}

/// `GET /v1/chain/list` — the SUPPORTED chains (profiles with a deployed
/// AgentKeys contract set — heima + base mainnet today) plus which one the
/// daemon operates on; the daemon's own chain is always included. Backs the
/// web chain switcher; selecting a chain is per-request via
/// `/v1/chain/info?chain=`, never daemon state.
async fn chain_list(State(state): State<SharedUiBridgeState>) -> Json<serde_json::Value> {
    let chains: Vec<serde_json::Value> =
        agentkeys_core::chain_profile::ChainProfile::list_builtin_names()
            .into_iter()
            .filter_map(|n| agentkeys_core::chain_profile::ChainProfile::load_builtin(n).ok())
            .filter(|p| {
                profile_is_supported(p) || p.name.eq_ignore_ascii_case(&state.chain_profile.name)
            })
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "display": p.display_name,
                    "chainId": p.chain_id,
                    "contracts": p.contracts.len(),
                })
            })
            .collect();
    Json(serde_json::json!({
        "chains": chains,
        "daemonChain": state.chain_profile.name,
        "daemonBroker": state.broker_url,
    }))
}

/// `GET /v1/audit/:id/decode` — decode one audit event's CBOR `AuditEnvelope`
/// and the on-chain calldata it commits, against the verified ABIs (#153). The
/// real replacement for the web UI's `decodeCalldata` mock.
async fn decode_audit_event(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorBody>)> {
    let event = {
        let guard = state.audit.read().await;
        guard.iter().find(|e| e.id == id).cloned()
    }
    .ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "audit event not found",
            "no-such-event",
        )
    })?;

    // Resolve the real omnis: the event's actor, and the master (operator).
    let (actor_omni, operator_omni) = {
        let actors = state.actors.read().await;
        let actor_omni = actors.get(&event.actor_id).map(|a| a.omni_hex.clone());
        let operator_omni = actors
            .values()
            .find(|a| a.role.eq_ignore_ascii_case("master"))
            .map(|a| a.omni_hex.clone());
        (actor_omni, operator_omni)
    };

    let mut decoded = crate::audit_decode::decode_event(
        &event,
        actor_omni.as_deref(),
        operator_omni.as_deref(),
        &state.chain_profile,
    );

    // #97: when the event carries real submit receipts, fetch the ACTUAL
    // envelopes from the audit worker by hash and replace the synthesized
    // preview. Best-effort — any fetch/decode failure keeps the preview (the
    // decode endpoint never hard-fails on worker downtime).
    if let (Some(worker_url), Some(hashes)) = (
        state.audit_worker_url.as_ref(),
        event
            .audit_envelope_hashes
            .as_ref()
            .filter(|h| !h.is_empty()),
    ) {
        let client = agentkeys_core::audit::AuditClient::new(worker_url.as_str());
        let mut real = Vec::new();
        for h in hashes {
            match client.get_envelope(h).await {
                Ok(Some(cbor)) => {
                    match agentkeys_core::audit::AuditEnvelope::from_canonical_cbor(&cbor) {
                        Ok(env) => real.push(env.to_json()),
                        Err(e) => tracing::warn!(
                            hash = %h, error = %e,
                            "audit decode: fetched envelope failed to decode — keeping preview"
                        ),
                    }
                }
                Ok(None) => tracing::warn!(
                    hash = %h,
                    "audit decode: envelope not found at the audit worker — keeping preview"
                ),
                Err(e) => tracing::warn!(
                    hash = %h, error = %e,
                    "audit decode: envelope fetch failed — keeping preview"
                ),
            }
        }
        overlay_real_envelopes(&mut decoded, real, event.tx_hash.as_deref());
    } else if let Some(tx) = event.tx_hash.as_deref() {
        decoded["tx_hash"] = serde_json::json!(tx);
    }

    // Decode the scope `serviceHash`es into readable names (`memory:<ns>` /
    // `inbox:<ns>` / the actors' cred services) so the audit view shows the GRANT
    // SET, not raw keccak hashes (the "can't read which grants are in the set"
    // gap). Annotates each envelope's `op_body` with a `service_names` array the
    // frontend renders alongside `service_ids`; unknown hashes pass through labeled.
    let actor_services: Vec<String> = {
        let actors = state.actors.read().await;
        actors
            .values()
            .filter_map(|a| a.services.clone())
            .flatten()
            .collect()
    };
    annotate_service_names(&mut decoded, &scope_name_map(&actor_services));

    Ok(Json(decoded))
}

/// Build a `serviceHash` (`0x`-hex keccak) → human-readable service-name map: the
/// `memory:<ns>` + DISTINCT `inbox:<ns>` grants for every namespace (#339), each
/// actor's cred services (`<svc>` and `cred:<svc>`), and a few well-known worker
/// services. The reverse of the on-chain keccak the broker/`heima-scope-set` write.
fn scope_name_map(actor_services: &[String]) -> HashMap<String, String> {
    let mut candidates: Vec<String> = Vec::new();
    for ns in SCOPE_NAMESPACES {
        candidates.push(format!("memory:{ns}"));
        candidates.push(format!("inbox:{ns}"));
    }
    for svc in actor_services {
        candidates.push(svc.clone());
        candidates.push(format!("cred:{svc}"));
    }
    for k in ["email", "mail:send", "mail:inbox", "audit:append"] {
        candidates.push(k.to_string());
    }
    let mut map = HashMap::new();
    for name in candidates {
        let h = format!(
            "0x{}",
            hex::encode(agentkeys_core::device_crypto::keccak256(name.as_bytes()))
        );
        map.entry(h).or_insert(name);
    }
    map
}

/// Annotate every decoded envelope's `op_body.service_ids` (raw keccak hashes) with
/// a parallel `service_names` array so the audit decode view is readable. Unknown
/// hashes pass through labeled (`unknown · 0x…`) so nothing is silently dropped.
fn annotate_service_names(decoded: &mut serde_json::Value, name_map: &HashMap<String, String>) {
    fn names_for(ids: &serde_json::Value, map: &HashMap<String, String>) -> serde_json::Value {
        let names: Vec<serde_json::Value> = ids
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        let raw = v.as_str().unwrap_or_default();
                        let name = map
                            .get(&raw.to_lowercase())
                            .cloned()
                            .unwrap_or_else(|| format!("unknown · {raw}"));
                        serde_json::Value::String(name)
                    })
                    .collect()
            })
            .unwrap_or_default();
        serde_json::Value::Array(names)
    }
    fn annotate_one(env: &mut serde_json::Value, map: &HashMap<String, String>) {
        let Some(ids) = env
            .get("op_body")
            .and_then(|b| b.get("service_ids"))
            .cloned()
        else {
            return;
        };
        if !ids.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
            return;
        }
        let names = names_for(&ids, map);
        if let Some(body) = env.get_mut("op_body").and_then(|b| b.as_object_mut()) {
            body.insert("service_names".to_string(), names);
        }
    }
    annotate_one(&mut decoded["envelope"], name_map);
    if let Some(envs) = decoded.get_mut("envelopes").and_then(|e| e.as_array_mut()) {
        for env in envs.iter_mut() {
            annotate_one(env, name_map);
        }
    }
}

/// #97: overlay REAL fetched envelopes onto a synthesized decode preview. The
/// envelope half becomes authoritative (`synthesized: false`); the calldata
/// half stays a reconstruction (noted in the provenance line). No-op when
/// nothing was fetched, so a worker outage degrades to the preview.
fn overlay_real_envelopes(
    base: &mut serde_json::Value,
    envelopes: Vec<serde_json::Value>,
    tx_hash: Option<&str>,
) {
    if let Some(tx) = tx_hash {
        base["tx_hash"] = serde_json::json!(tx);
    }
    if envelopes.is_empty() {
        return;
    }
    base["synthesized"] = serde_json::json!(false);
    base["provenance"] = serde_json::json!(
        "real · envelope(s) fetched from the audit worker by the submit receipt \
         hashes (verify: keccak256(canonical_cbor) == envelope_hash); the decoded \
         calldata panel remains a reconstruction"
    );
    base["envelope"] = envelopes[0].clone();
    base["envelopes"] = serde_json::json!(envelopes);
}

async fn list_workers(State(state): State<SharedUiBridgeState>) -> impl IntoResponse {
    let guard = state.workers.read().await;
    let mut workers: Vec<ApiWorker> = guard.values().cloned().collect();
    workers.sort_by(|a, b| a.id.cmp(&b.id));
    Json(serde_json::json!({ "workers": workers }))
}

async fn get_worker(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> Result<Json<ApiWorker>, (StatusCode, Json<ErrorBody>)> {
    let guard = state.workers.read().await;
    guard
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such worker", "worker-not-found"))
}

// ─── Dev seed (operator-only, debug data injection) ────────────────────

#[derive(Debug, Deserialize)]
pub struct DevSeedRequest {
    #[serde(default)]
    pub actors: Vec<ApiActor>,
    #[serde(default)]
    pub caps: HashMap<String, Vec<ApiCapToken>>,
    #[serde(default)]
    pub workers: Vec<ApiWorker>,
    #[serde(default)]
    pub anchor: Option<ApiAnchorStatus>,
    #[serde(default)]
    pub audit: Vec<ApiAuditEvent>,
    #[serde(default)]
    pub master_memory: Vec<ApiMemoryEntry>,
}

async fn dev_seed(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DevSeedRequest>,
) -> impl IntoResponse {
    {
        let mut actors = state.actors.write().await;
        for a in req.actors {
            actors.insert(a.id.clone(), a);
        }
    }
    {
        let mut caps = state.caps.write().await;
        for (k, v) in req.caps {
            caps.insert(k, v);
        }
    }
    {
        let mut workers = state.workers.write().await;
        for w in req.workers {
            workers.insert(w.id.clone(), w);
        }
    }
    if let Some(a) = req.anchor {
        *state.anchor.write().await = a;
    }
    if !req.master_memory.is_empty() {
        let mut mem = state.master_memory.write().await;
        for mut e in req.master_memory {
            let hash = if e.content_hash.is_empty() {
                e.compute_hash()
            } else {
                e.content_hash.clone()
            };
            e.content_hash = hash.clone();
            mem.insert(hash, e);
        }
    }
    for evt in req.audit {
        push_audit(&state, evt).await;
    }
    Json(serde_json::json!({ "ok": true }))
}

async fn dev_emit_event(
    State(state): State<SharedUiBridgeState>,
    Json(evt): Json<ApiAuditEvent>,
) -> impl IntoResponse {
    push_audit(&state, evt).await;
    Json(serde_json::json!({ "ok": true }))
}

// ─── Master memory — list + idempotent plant (§2 "plant preserved memory") ──

/// `GET /v1/master/memory` → the memory CATEGORIES, resolved from the durable,
/// master-only Config-class taxonomy (#178 §7 / #201) with **zero memory
/// decryption**. Falls back to cache-derived categories ONLY when Config is
/// unconfigured or the taxonomy is confirmed missing; a configured-but-failing
/// Config surfaces as 502 (codex finding 2 — never hide a broken Config behind a
/// stale "looks empty" view). Per-entry detail is lazy via `.../memory/entry`.
/// GET /v1/agent/pairing/pending — the web-app half of §10.2 agent pairing
/// (issue #214). The master pulls the broker's pending agent bindings (agents it
/// claimed that await on-chain register) via its J1 session, mapped to the web
/// UI's `PairingRequest` shape. REAL data — broker `/v1/agent/pending-bindings`
/// (reuses `agentkeys_cli::agent_admin`, the CLI master-side pairing client).
async fn list_pairing_requests(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "no broker configured (--broker-url) — cannot pull pending agent pairings"
            })),
        )
            .into_response();
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "no master session — verify email + register the master first"
                })),
            )
                .into_response()
        }
    };
    match agentkeys_cli::agent_admin::agent_pending_value(broker, &j1).await {
        Ok(v) => {
            let requests: Vec<serde_json::Value> = v
                .get("pending")
                .and_then(|p| p.as_array())
                .map(|rows| rows.iter().map(pending_binding_to_request).collect())
                .unwrap_or_default();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "requests": requests })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("broker pending-bindings: {e:#}") })),
        )
            .into_response(),
    }
}

/// Map one broker `PendingBinding` row → the web UI's `PairingRequest` JSON
/// (`apps/parent-control/app/_components/types.ts`). These rows are POST-claim
/// (awaiting on-chain approval); `pairCode` carries the agent's REAL one-time
/// pairing code (the master claimed by it) so the operator can confirm it matches
/// the device, `requestedAt` carries the broker `created_at` unix seconds, and
/// (#224) `expiresAt` carries the broker `expires_at` — the SAME value the agent
/// printed — so the card renders a live countdown (a stale card reads as expired).
fn pending_binding_to_request(b: &serde_json::Value) -> serde_json::Value {
    let field = |k: &str| {
        b.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let request_id = field("request_id");
    let label = field("label");
    let device_pubkey = field("device_pubkey");
    let device_key_hash = field("device_key_hash");
    let pop_sig = field("pop_sig");
    let requested_scope = field("requested_scope");
    let pairing_code = field("pairing_code");
    // created_at: broker unix seconds (the agent's /request). The UI formats it.
    let created_at = b
        .get("created_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    // #224 expires_at: broker unix seconds the request expires — the SAME value the
    // agent's `--request-pairing` prints. The UI renders a live countdown so a stale
    // card (already past expiry / an old start) is visibly the one to refuse.
    let expires_at = b
        .get("expires_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    // char-safe head…tail elision for long hex handles.
    let short = |v: &str| -> String {
        let n = v.chars().count();
        if n > 18 {
            let head: String = v.chars().take(10).collect();
            let tail: String = v.chars().skip(n - 6).collect();
            format!("{head}…{tail}")
        } else {
            v.to_string()
        }
    };
    // requested_scope: comma-separated "<service>:<ns>" tokens → RequestedPerm[].
    let requested: Vec<serde_json::Value> = requested_scope
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|tok| {
            let (cap, ns) = match tok.split_once(':') {
                Some((c, n)) => (
                    c.to_string(),
                    vec![serde_json::Value::String(n.to_string())],
                ),
                None => (tok.to_string(), Vec::new()),
            };
            serde_json::json!({ "cap": cap, "ns": ns, "reason": "requested at pairing" })
        })
        .collect();
    // #408 D6 — a claim whose scope is ONLY channel-pub/sub grants is a channel-
    // endpoint DEVICE bind (same predicate the broker's poll uses for the D9
    // no-spawn). The web app routes device claims to the channel section and
    // sandbox-delegate claims to the pairing section on this flag.
    let is_device = agentkeys_backend_client::protocol::scope_is_device_only(&requested_scope);
    // The declared column is self-reported placeholder context either way
    // (never a basis for approval) — but the sandbox wording is WRONG for a
    // device claim, so vary it by the derived kind.
    let (device_lbl, machine_lbl, runtime_lbl) = if is_device {
        (
            "channel-endpoint device (K10)",
            "device",
            "none — channel endpoint (no runtime)",
        )
    } else {
        ("sandbox device (K10)", "aiosandbox", "hermes")
    };
    serde_json::json!({
        "id": request_id,
        "agent": label,
        "vendor": if is_device { "device" } else { "agent" },
        "device": device_lbl,
        "machine": machine_lbl,
        "runtime": runtime_lbl,
        "isDevice": is_device,
        "dpub": short(&device_pubkey),
        "dpubFull": device_pubkey,
        // #224: the operator cross-checks `deviceKeyHash` (+ `dpubFull`, both printed
        // by the agent's `--request-pairing`) before `accept · Touch ID`. `id` is the
        // full request_id (the master-side handle). `pairCode` is now the agent's REAL
        // one-time code (the master claimed by it) — shown so the operator can confirm
        // it matches the code on the agent device.
        "deviceKeyHash": device_key_hash.clone(),
        "deviceKeyHashShort": short(&device_key_hash),
        "pairCode": pairing_code,
        "derivation": format!("//{label}"),
        "requested": requested,
        "requestedAt": created_at,
        "expiresAt": expires_at,
        "attestation": format!("PoP verified · {}", short(&pop_sig)),
    })
}

#[derive(Debug, Deserialize)]
struct ClaimPairingRequest {
    pairing_code: String,
    label: String,
    #[serde(default)]
    requested_scope: String,
}

/// POST /v1/agent/pairing/decline — forward the master's decline to the broker
/// (removes the pending rendezvous row so it stops reappearing). J1-gated, **no
/// Touch ID** — declining isn't an on-chain mutation. Untyped relay, like the
/// accept proxies.
async fn decline_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    forward_to_broker(&broker, "/v1/agent/pairing/decline", &j1, &body).await
}

/// POST /v1/agent/pairing/ack — mark a claimed pairing as BOUND so the broker drops
/// it from the pending list. The E7 accept (`/v1/accept/{build,submit}`) registers the
/// agent on-chain but its `SubmitAcceptRequest` carries no `request_id`, so the broker
/// can't drop the rendezvous row itself — the master acks it here (the same
/// `mark_bound` the legacy `register_pairing` path runs). Without this, an accepted
/// request keeps reappearing in `GET /v1/agent/pairing/pending`. J1-gated, **no Touch
/// ID** (acking isn't an on-chain mutation — the accept already did that). Forwards
/// `{request_id}` to the broker's `/v1/agent/pending-bindings/ack`.
async fn ack_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    // #233 follow-up (real 2026-06-10 incident): the E7 accept path never
    // inserted the freshly-bound agent into `state.actors` (only the legacy
    // register_pairing did), and the post-restart chain sync is LATCHED — so an
    // accepted agent stayed invisible on the actor page until a daemon restart.
    // Capture the pending row (label, child omni, device hash) BEFORE the ack
    // drops it, then surface the actor + un-latch the chain sync. Best-effort:
    // a failed lookup never blocks the ack (the un-latch alone lets the next
    // actor read reconcile the new device from chain, placeholder-labelled).
    let request_id = body
        .get("request_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let pending_row = match agentkeys_cli::agent_admin::agent_pending_value(&broker, &j1).await {
        Ok(v) => v
            .get("pending")
            .and_then(|p| p.as_array())
            .and_then(|rows| {
                rows.iter()
                    .find(|r| {
                        r.get("request_id").and_then(|v| v.as_str()) == Some(request_id.as_str())
                    })
                    .cloned()
            }),
        Err(_) => None,
    };
    let resp = forward_to_broker(&broker, "/v1/agent/pending-bindings/ack", &j1, &body).await;
    if resp.status().is_success() {
        if let Some(row) = pending_row {
            let field = |k: &str| {
                row.get(k)
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string()
            };
            let label = field("label");
            let actor_omni = field("child_omni");
            let device_key_hash = field("device_key_hash");
            if !label.is_empty() && !actor_omni.is_empty() {
                let omni_hex = if actor_omni.starts_with("0x") {
                    actor_omni.clone()
                } else {
                    format!("0x{actor_omni}")
                };
                // #408: the accept proxy stashed the FINAL granted service names +
                // device flag under this request_id — consume them so the actor
                // row is named (channel chips, audit decode) and device-labelled.
                // Fallback: the claim's requested_scope tokens (legacy register
                // path, or a build that never ran through this daemon).
                let stashed = state
                    .accept_grants_by_request
                    .write()
                    .await
                    .remove(&request_id);
                let (services, was_device_accept) = match stashed {
                    Some((svcs, dev)) => (svcs, dev),
                    None => {
                        let scope = field("requested_scope");
                        let toks: Vec<String> = scope
                            .split([',', ' '])
                            .map(str::trim)
                            .filter(|t| !t.is_empty())
                            .map(str::to_string)
                            .collect();
                        let dev = agentkeys_backend_client::protocol::scope_is_device_only(&scope);
                        (toks, dev)
                    }
                };
                // #424 §1 — the accept is the durability boundary: persist this
                // actor's readable metadata (kind + granted NAMES) to the
                // Config-class binding manifest so it survives a daemon restart
                // (the chain row alone can never recover them). Best-effort:
                // a store failure warns loudly, never blocks the ack.
                let manifest_entry = BindingManifestEntry {
                    actor_omni: omni_hex.clone(),
                    device_key_hash: device_key_hash.clone(),
                    label: label.clone(),
                    kind: if was_device_accept {
                        "device".into()
                    } else {
                        "delegate".into()
                    },
                    granted_service_names: services.clone(),
                    updated_at: now_unix(),
                    // #427 fields ride only the spawn ceremony; a pairing
                    // accept states none (upsert preserves any existing).
                    preset_id: None,
                    memory_ns: None,
                    archived_at: None,
                    resources_kept: None,
                };
                let agent_actor = ApiActor {
                    id: format!("agent-{label}"),
                    omni: omni_hex.clone(),
                    omni_hex,
                    label: label.clone(),
                    role: "agent".into(),
                    parent: Some("master".into()),
                    derivation: format!("//{label}"),
                    device: if was_device_accept {
                        "channel-endpoint device (§10.2)".into()
                    } else {
                        "sandbox device (§10.2)".into()
                    },
                    device_pubkey: field("device_pubkey"),
                    last_active: "just paired".into(),
                    status: "ok".into(),
                    vendor: if was_device_accept {
                        "device".into()
                    } else {
                        String::new()
                    },
                    k11: false,
                    device_key_hash: (!device_key_hash.is_empty()).then(|| {
                        if device_key_hash.starts_with("0x") {
                            device_key_hash.clone()
                        } else {
                            format!("0x{device_key_hash}")
                        }
                    }),
                    scope: None,
                    scope_unknown_service_ids: None,
                    payment_cap: None,
                    time_window: None,
                    services: (!services.is_empty()).then_some(services),
                    account_address: None,
                    account_type: None,
                    preset_id: None,
                    memory_ns: None,
                };
                state
                    .actors
                    .write()
                    .await
                    .insert(agent_actor.id.clone(), agent_actor);
                upsert_binding_manifest_entry(&state, manifest_entry).await;
                tracing::info!(
                    target: "agentkeys.daemon.ui_bridge",
                    label = %label,
                    "accepted agent surfaced in the actor tree"
                );
            }
        }
        invalidate_fleet_sync(&state);
    }
    resp
}

/// POST /v1/agent/pairing/claim — the master claims an agent's one-time pairing
/// code (#214, §10.2 P.1). Binds the agent under the HDKD child omni for `label`
/// and declares its requested scope, via the broker, using the master's J1
/// session. The agent then surfaces in pending-bindings (GET …/pending) awaiting
/// the master's on-chain register. Reuses `agentkeys_cli::agent_admin::agent_claim`.
async fn claim_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ClaimPairingRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "no broker configured (--broker-url)" })),
        )
            .into_response();
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "no master session — verify email + register the master first"
                })),
            )
                .into_response()
        }
    };
    let code = req.pairing_code.trim();
    let label = req.label.trim();
    if code.is_empty() || label.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "pairing_code and label are required" })),
        )
            .into_response();
    }
    match agentkeys_cli::agent_admin::agent_claim(broker, code, label, &req.requested_scope, &j1)
        .await
    {
        Ok(body) => {
            let claim: serde_json::Value =
                serde_json::from_str(&body).unwrap_or_else(|_| serde_json::json!({ "ok": true }));
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "claim": claim })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("agent claim: {e:#}") })),
        )
            .into_response(),
    }
}

fn pairing_err(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

#[derive(Debug, Deserialize)]
struct RegisterPairingRequest {
    request_id: String,
}

/// #225 / #164 E7 — the Touch-ID-gated accept (slice 4: daemon proxy). The browser
/// calls `build` (→ broker assembles the sponsored executeBatch UserOp + returns the
/// `userOpHash`), does `navigator.credentials.get()` (Touch ID) over that hash, then
/// calls `submit` with the signed op. The daemon forwards both to the broker with the
/// master J1; the device fields come from the broker's AUTHORITATIVE binding (never
/// the browser), the scope from the master's UI approval.
#[derive(Debug, Deserialize)]
pub struct DaemonAcceptBuildRequest {
    pub request_id: String,
    pub services: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
    /// #408 — the accept card declares the claim a channel-endpoint DEVICE bind
    /// (spec §14.10: the card hard-enforces ≥1 channel; the broker warns).
    /// Forwarded to the broker's `BuildAcceptRequest.is_device` — omitting it
    /// here was the gap that made the broker warn unreachable from the web.
    #[serde(default)]
    pub is_device: bool,
}

/// POST /v1/accept/build — resolve the binding + forward to the broker's
/// `/v1/accept/build`, returning the `userOpHash` the browser K11-signs.
async fn accept_build_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DaemonAcceptBuildRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let bindings = match agentkeys_cli::agent_admin::agent_pending_value(&broker, &j1).await {
        Ok(v) => v,
        Err(e) => return pairing_err(StatusCode::BAD_GATEWAY, &format!("broker pending: {e:#}")),
    };
    let row = bindings
        .get("pending")
        .and_then(|p| p.as_array())
        .and_then(|rows| {
            rows.iter()
                .find(|r| {
                    r.get("request_id").and_then(|v| v.as_str()) == Some(req.request_id.as_str())
                })
                .cloned()
        });
    let Some(row) = row else {
        return pairing_err(
            StatusCode::NOT_FOUND,
            "no pending binding for that request_id",
        );
    };
    let field = |k: &str| {
        row.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let mut body = serde_json::json!({
        "operator_omni": operator_omni,
        "actor_omni": field("child_omni"),
        "device_key_hash": field("device_key_hash"),
        "agent_pop_sig": field("pop_sig"),
        "link_code_redemption": "0x", // accepted-but-unused by registerAgentDevice
        "services": req.services,
        "read_only": req.read_only,
        "max_per_call": req.max_per_call,
        "max_per_period": req.max_per_period,
        "max_total": req.max_total,
        "period_seconds": req.period_seconds,
    });
    // #408: present only when true — keeps the delegate body byte-identical to
    // the pre-#408 shape (mirrors the protocol type's skip_serializing_if).
    if req.is_device {
        body["is_device"] = serde_json::json!(true);
    }
    // Stash the operator's FINAL grant set (the picker may have edited the
    // claim's requested_scope) so ack_pairing can surface the actor with the
    // service NAMES the accept actually granted — chain stores only keccak ids.
    state.accept_grants_by_request.write().await.insert(
        req.request_id.clone(),
        (req.services.clone(), req.is_device),
    );
    forward_to_broker(&broker, "/v1/accept/build", &j1, &body).await
}

/// POST /v1/accept/submit — forward the K11-signed op to the broker's
/// `/v1/accept/submit` (→ EntryPoint.handleOps).
async fn accept_submit_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let (resp, parsed) = forward_to_broker_value(&broker, "/v1/accept/submit", &j1, &body).await;
    if resp.status().is_success() {
        // The accept just registered an agent on chain — un-latch the #233 sync
        // so the actor tree reflects it even if the follow-up ack is skipped.
        invalidate_fleet_sync(&state);
        // #97: the broker's submit relay decoded the landed executeBatch and
        // emitted the DeviceAdd + ScopeGrant envelopes — record the confirmed
        // chain commit in the audit feed with the REAL receipts (the decode
        // view fetches the envelopes by these hashes instead of synthesizing).
        let (tx_hash, audit_envelope_hashes) =
            parsed.as_ref().map(submit_receipts).unwrap_or((None, None));
        let evt = ApiAuditEvent {
            id: format!("e-accept-{}", now_unix()),
            ts: now_ts_hms(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "device.paired".into(),
            detail: format!(
                "agent accept landed on chain (registerAgentDevice + setScope, one block){}",
                tx_hash
                    .as_deref()
                    .map(|h| format!(" · tx={h}"))
                    .unwrap_or_default()
            ),
            chip: "pairing".into(),
            sev: "ok".into(),
            tx_hash,
            audit_envelope_hashes,
        };
        push_audit(&state, evt).await;
    }
    resp
}

/// #427 — the parent-control spawn ceremony, daemon half. The browser sends
/// only the ceremony choices; the daemon fills `operator_omni` from the master
/// session (never the browser) and forwards to the broker's
/// `/v1/agent/spawn/build`, stashing the returned ceremony context (label,
/// preset, namespace, template service NAMES) by `device_key_hash` so the
/// submit proxy can write the #424 binding-manifest row on confirm.
#[derive(Debug, Deserialize)]
pub struct DaemonSpawnBuildRequest {
    pub label: String,
    #[serde(default)]
    pub preset_id: String,
    #[serde(default)]
    pub memory_ns: Option<String>,
    #[serde(default)]
    pub memory_inherited: bool,
}

/// POST /v1/agent/spawn/build — forward to the broker (#427); the body shape is
/// crate-owned (`agentkeys_backend_client::protocol::BuildSpawnUserOpRequest`).
async fn spawn_build_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DaemonSpawnBuildRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let mut body = serde_json::json!({
        "operator_omni": operator_omni,
        "label": req.label,
        "preset_id": req.preset_id,
    });
    if let Some(ns) = &req.memory_ns {
        body["memory_ns"] = serde_json::json!(ns);
    }
    if req.memory_inherited {
        body["memory_inherited"] = serde_json::json!(true);
    }
    let (resp, parsed) =
        forward_to_broker_value(&broker, "/v1/agent/spawn/build", &j1, &body).await;
    if resp.status().is_success() {
        if let Some(built) = parsed.as_ref() {
            if let Some(dkh) = built.get("device_key_hash").and_then(|v| v.as_str()) {
                // Stash the readable ceremony context the manifest row needs
                // at submit-confirm (chain stores only keccak ids + hashes).
                state
                    .ceremony_context_by_dkh
                    .write()
                    .await
                    .insert(dkh.to_lowercase(), built.clone());
            }
        }
    }
    resp
}

/// POST /v1/agent/spawn/submit — forward the K11-signed spawn op to the broker;
/// on a CONFIRMED ceremony write the #424 binding-manifest row (kind=delegate,
/// preset, label, template grant names, memory namespace) and un-latch the
/// fleet sync.
async fn spawn_submit_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let (resp, parsed) =
        forward_to_broker_value(&broker, "/v1/agent/spawn/submit", &j1, &body).await;
    if resp.status().is_success() {
        invalidate_fleet_sync(&state);
        for spawned in parsed
            .as_ref()
            .and_then(|v| v.pointer("/ceremony/spawned"))
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let dkh = spawned
                .get("device_key_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let stashed = state.ceremony_context_by_dkh.write().await.remove(&dkh);
            let ctx = stashed.as_ref().unwrap_or(spawned);
            let sfield = |v: &serde_json::Value, k: &str| {
                v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
            };
            let services = ctx
                .get("services")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let label = {
                let l = sfield(spawned, "label");
                if l.is_empty() {
                    sfield(ctx, "label")
                } else {
                    l
                }
            };
            upsert_binding_manifest_entry(
                &state,
                BindingManifestEntry {
                    actor_omni: sfield(ctx, "actor_omni"),
                    device_key_hash: dkh,
                    label,
                    kind: "delegate".into(),
                    granted_service_names: services,
                    updated_at: now_unix(),
                    preset_id: Some(sfield(spawned, "preset_id")),
                    memory_ns: Some(sfield(ctx, "memory_ns")),
                    archived_at: None,
                    resources_kept: None,
                },
            )
            .await;
            // #430 — name the opchat channel so its grant chips render
            // readably after restarts.
            let chat_id = sfield(ctx, "chat_channel_id");
            if !chat_id.is_empty() {
                let display = {
                    let l = sfield(spawned, "label");
                    if l.is_empty() {
                        sfield(ctx, "label")
                    } else {
                        l
                    }
                };
                ensure_channel_named(&state, &chat_id, &format!("Chat · {display}")).await;
            }
            // #428 — distribute the preset content into the fresh delegate
            // (persona canonical + sandbox apply + skills docs). Best-effort
            // loud; the ceremony is already final on-chain.
            let preset_id = sfield(spawned, "preset_id");
            let delegate_omni = sfield(ctx, "actor_omni");
            let sandbox_id = spawned
                .pointer("/sandbox/sandbox_id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            if !preset_id.is_empty() && !delegate_omni.is_empty() {
                apply_preset_at_spawn(
                    &state,
                    &broker,
                    &preset_id,
                    &delegate_omni,
                    sandbox_id.as_deref(),
                )
                .await;
            }
        }
    }
    resp
}

/// #427 — the archive ceremony, daemon half.
#[derive(Debug, Deserialize)]
pub struct DaemonArchiveBuildRequest {
    pub device_key_hash: String,
    #[serde(default)]
    pub resources_kept: bool,
    #[serde(default)]
    pub memory_ns: Option<String>,
}

/// POST /v1/agent/archive/build — forward to the broker (#427).
async fn archive_build_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DaemonArchiveBuildRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let mut body = serde_json::json!({
        "operator_omni": operator_omni,
        "device_key_hash": req.device_key_hash,
    });
    if req.resources_kept {
        body["resources_kept"] = serde_json::json!(true);
    }
    if let Some(ns) = &req.memory_ns {
        body["memory_ns"] = serde_json::json!(ns);
    }
    forward_to_broker(&broker, "/v1/agent/archive/build", &j1, &body).await
}

/// POST /v1/agent/archive/submit — forward; on a CONFIRMED archive mark the
/// manifest row archived (RETAINED, per the epic acceptance — a kept namespace
/// stays discoverable for #425 O2 inheritance) and un-latch the fleet sync.
async fn archive_submit_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let (resp, parsed) =
        forward_to_broker_value(&broker, "/v1/agent/archive/submit", &j1, &body).await;
    if resp.status().is_success() {
        invalidate_fleet_sync(&state);
        for archived in parsed
            .as_ref()
            .and_then(|v| v.pointer("/ceremony/archived"))
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let dkh = archived
                .get("device_key_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let kept = archived
                .get("resources_kept")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let ns = archived
                .get("memory_ns")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            mark_binding_archived(&state, dkh, kept, ns).await;
        }
    }
    resp
}

/// Mark a manifest row archived in place (retained, never deleted — the row is
/// the O2 inheritance-discovery record). Missing row = WARN, not an error.
async fn mark_binding_archived(
    state: &UiBridgeState,
    device_key_hash: &str,
    resources_kept: bool,
    memory_ns: Option<String>,
) {
    let mut manifest = match ensure_binding_manifest(state).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                device_key_hash = %device_key_hash,
                "binding manifest LOAD failed on archive — {e}"
            );
            return;
        }
    };
    let Some(entry) = manifest.entry_for("", device_key_hash).cloned() else {
        tracing::warn!(
            target: "agentkeys.daemon.ui_bridge",
            device_key_hash = %device_key_hash,
            "archive confirmed but no manifest row to mark (headless spawn or pre-#427 binding)"
        );
        return;
    };
    let mut updated = entry;
    updated.archived_at = Some(now_unix());
    updated.resources_kept = Some(resources_kept);
    if updated.memory_ns.is_none() {
        updated.memory_ns = memory_ns;
    }
    updated.updated_at = now_unix();
    manifest.upsert(updated);
    match persist_binding_manifest(state, manifest).await {
        Ok(storage) => tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            device_key_hash = %device_key_hash,
            resources_kept,
            storage,
            "binding manifest row marked archived"
        ),
        Err(e) => tracing::warn!(
            target: "agentkeys.daemon.ui_bridge",
            device_key_hash = %device_key_hash,
            "binding manifest archive-mark persist FAILED — {e}"
        ),
    }
}

/// #429 — `GET /v1/agent/inheritable-namespaces`: the kept namespaces of
/// ARCHIVED delegates a spawn may inherit (#425 O2). A namespace qualifies
/// when its manifest row is archived with `resources_kept` AND no LIVE
/// delegate row currently holds the same `memory_ns` — "inheritable by at
/// most one live delegate at a time" is enforced by construction here (the
/// spawn modal only offers what this returns).
async fn list_inheritable_namespaces(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    if let Err(resp) = require_master_session(&state).await {
        return resp;
    }
    let manifest = match ensure_binding_manifest(&state).await {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": format!("binding manifest: {e}") })),
            )
                .into_response()
        }
    };
    let live_held: std::collections::HashSet<String> = manifest
        .entries()
        .iter()
        .filter(|e| e.kind == "delegate" && e.archived_at.is_none())
        .filter_map(|e| e.memory_ns.clone())
        .collect();
    // Latest archive wins per namespace (a ns can cycle through delegates).
    let mut by_ns: std::collections::HashMap<String, (String, u64)> =
        std::collections::HashMap::new();
    for e in manifest.entries() {
        let (Some(at), Some(true), Some(ns)) =
            (e.archived_at, e.resources_kept, e.memory_ns.clone())
        else {
            continue;
        };
        if live_held.contains(&ns) {
            continue;
        }
        match by_ns.get(&ns) {
            Some((_, prev)) if *prev >= at => {}
            _ => {
                by_ns.insert(ns, (e.label.clone(), at));
            }
        }
    }
    let mut namespaces: Vec<serde_json::Value> = by_ns
        .into_iter()
        .map(|(ns, (from_label, archived_at))| {
            serde_json::json!({ "ns": ns, "from_label": from_label, "archived_at": archived_at })
        })
        .collect();
    namespaces.sort_by(|a, b| b["archived_at"].as_u64().cmp(&a["archived_at"].as_u64()));
    Json(serde_json::json!({ "namespaces": namespaces })).into_response()
}

/// #430 — auto-register a spawn's opchat channel id with a display name, so
/// its grants render with a NAME after daemon restarts (the registry is the
/// id→name dictionary; the keccak re-name map alone yields a raw-id chip).
/// Insert-if-absent; best-effort loud.
async fn ensure_channel_named(state: &UiBridgeState, id: &str, name: &str) {
    if !valid_channel_id(id) {
        return;
    }
    let mut registry = match ensure_channel_registry(state).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                id,
                "channel registry LOAD failed for opchat auto-name — {e}"
            );
            return;
        }
    };
    if registry.channels.iter().any(|c| c.id == id) {
        return;
    }
    registry.channels.push(ApiChannel {
        id: id.to_string(),
        name: name.to_string(),
        note: Some("auto-registered at spawn (#430 operator chat)".to_string()),
        created_at: now_unix(),
    });
    match persist_channel_registry(state, registry).await {
        Ok(storage) => tracing::info!(id, storage, "opchat channel auto-named"),
        Err(e) => tracing::warn!(id, "opchat auto-name persist FAILED — {e}"),
    }
}

// ── #430 — the master-side chat surface (operator-owned duplex feed, D8) ────

/// One rendered chat turn for the web app — the feed event with its payload
/// decoded (the raw `ChannelEvent` carries base64; the UI wants text).
#[derive(Debug, Clone, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiChatEvent {
    pub event_id: String,
    /// `"in"` = operator → delegate; `"out"` = the delegate's reply.
    pub direction: String,
    pub text: String,
    /// The cap-signed producer (worker-stamped provenance, §4.1).
    pub producer_omni: String,
    #[ts(type = "number")]
    pub ts_millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub correlation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChatSendRequest {
    pub channel_id: String,
    pub text: String,
}

#[derive(Debug, Deserialize)]
pub struct ChatPollRequest {
    pub channel_id: String,
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

/// The channel worker the daemon talks to — same env family as every worker
/// URL (`AGENTKEYS_WORKER_CHANNEL_URL`, wired by dev.sh / the host env files).
fn channel_worker_url() -> Result<String, String> {
    std::env::var("AGENTKEYS_WORKER_CHANNEL_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .ok_or_else(|| {
            "AGENTKEYS_WORKER_CHANNEL_URL not set — the chat surface needs the channel worker"
                .to_string()
        })
}

/// Master-self channel cap (operator == actor — the session-authenticated
/// operator path of the channel-kind matrix; no operator K10 involved beyond
/// the daemon's own device key for the #76 PoP when configured).
async fn master_channel_cap(
    state: &UiBridgeState,
    direction_service: String,
    op: agentkeys_backend_client::protocol::CapMintOp,
) -> Result<(serde_json::Value, SessionCoords), String> {
    let coords = resolve_session_coords(state).await?;
    let client = agentkeys_backend_client::BackendClient::new(
        Some(coords.broker.clone()),
        None,
        None,
        None,
        Some(coords.j1.clone()),
        None,
        None,
        coords.region.clone(),
    );
    let cap = client
        .cap_mint(
            op,
            agentkeys_backend_client::protocol::CapMintRequest {
                operator_omni: coords.omni.clone(),
                actor_omni: coords.omni.clone(),
                service: direction_service,
                device_key_hash: coords.device_key_hash.clone(),
                ttl_seconds: 120,
            },
            &coords.j1,
        )
        .await
        .map_err(|e| format!("channel cap mint: {e}"))?;
    let cap_json = serde_json::to_value(&cap).map_err(|e| format!("cap serialize: {e}"))?;
    Ok((cap_json, coords))
}

fn chat_event_from_value(v: &serde_json::Value) -> ApiChatEvent {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let text = v
        .get("body")
        .and_then(|b| b.as_str())
        .and_then(|b64| STANDARD.decode(b64).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| "(non-text event)".to_string());
    ApiChatEvent {
        event_id: v
            .get("event_id")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        direction: v
            .get("direction")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        text,
        producer_omni: v
            .pointer("/producer/actor_omni")
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string(),
        ts_millis: v.get("ts_millis").and_then(|n| n.as_u64()).unwrap_or(0),
        correlation: v
            .get("correlation")
            .and_then(|s| s.as_str())
            .map(str::to_string),
    }
}

/// `POST /v1/master/agent/chat/send` — publish one operator turn
/// (`direction: in`) into the delegate's opchat feed. The delegate's
/// in-sandbox loop consumes it and replies `direction: out`.
async fn master_chat_send(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ChatSendRequest>,
) -> axum::response::Response {
    if let Err(resp) = require_master_session(&state).await {
        return resp;
    }
    if !valid_channel_id(&req.channel_id) || req.text.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "channel_id (1-48 [a-z0-9-]) and text required" })),
        )
            .into_response();
    }
    let worker = match channel_worker_url() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let (cap, _coords) = match master_channel_cap(
        &state,
        format!("channel-pub:{}", req.channel_id),
        agentkeys_backend_client::protocol::CapMintOp::ChannelPublish,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    // @backend-fixture: channel_publish_body
    let body = serde_json::json!({
        "cap": cap,
        "kind": "text",
        "direction": "in",
        "body_b64": STANDARD.encode(req.text.as_bytes()),
    });
    match reqwest::Client::new()
        .post(format!("{worker}/v1/channel/publish"))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let st =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let txt = resp.text().await.unwrap_or_default();
            (
                st,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                txt,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("channel worker publish: {e}") })),
        )
            .into_response(),
    }
}

/// `POST /v1/master/agent/chat/poll` — the transcript read (D13: operator
/// session only) + the NRT long-poll for new turns.
async fn master_chat_poll(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ChatPollRequest>,
) -> axum::response::Response {
    if let Err(resp) = require_master_session(&state).await {
        return resp;
    }
    if !valid_channel_id(&req.channel_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid channel_id" })),
        )
            .into_response();
    }
    let worker = match channel_worker_url() {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    let (cap, _coords) = match master_channel_cap(
        &state,
        format!("channel-sub:{}", req.channel_id),
        agentkeys_backend_client::protocol::CapMintOp::ChannelSubscribe,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    // @backend-fixture: channel_poll_body
    let body = serde_json::json!({
        "cap": cap,
        "after": req.after,
        "wait_seconds": req.wait_seconds.min(25),
    });
    let resp = match reqwest::Client::new()
        .post(format!("{worker}/v1/channel/poll"))
        .timeout(std::time::Duration::from_secs(40))
        .json(&body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("channel worker poll: {e}") })),
            )
                .into_response()
        }
    };
    if !resp.status().is_success() {
        let st = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let txt = resp.text().await.unwrap_or_default();
        return (
            st,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            txt,
        )
            .into_response();
    }
    let v: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("poll parse: {e}") })),
            )
                .into_response()
        }
    };
    let events: Vec<ApiChatEvent> = v
        .get("events")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().map(chat_event_from_value).collect())
        .unwrap_or_default();
    let cursor = v
        .get("cursor")
        .and_then(|c| c.as_str())
        .unwrap_or_default()
        .to_string();
    Json(serde_json::json!({ "events": events, "cursor": cursor })).into_response()
}

/// #428 — spawn-time preset apply: fetch the bundle from the broker's
/// compiled-in catalog, seed the delegate's persona canonical (the #390 store
/// — versioned; the locked base layer is appended at apply) + apply it into
/// the FRESH sandbox (instance-routed via `x-faas-instance-name`), and
/// distribute the skills docs to `$HERMES_HOME/skills/`. Best-effort LOUD:
/// the on-chain ceremony is already final, so every failure surfaces in the
/// audit feed + logs and never fails the submit. Content, never authority —
/// nothing here grants anything beyond the phase-1 template.
async fn apply_preset_at_spawn(
    state: &SharedUiBridgeState,
    broker: &str,
    preset_id: &str,
    delegate_omni: &str,
    sandbox_id: Option<&str>,
) {
    let url = format!("{}/v1/presets/{}", broker.trim_end_matches('/'), preset_id);
    let bundle: agentkeys_backend_client::protocol::PresetBundle =
        match reqwest::Client::new().get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.json().await {
                Ok(b) => b,
                Err(e) => {
                    preset_apply_audit(
                        state,
                        preset_id,
                        delegate_omni,
                        format!("bundle parse failed: {e}"),
                        "warn",
                    )
                    .await;
                    return;
                }
            },
            Ok(resp) => {
                preset_apply_audit(
                    state,
                    preset_id,
                    delegate_omni,
                    format!("catalog fetch HTTP {} — unknown preset?", resp.status()),
                    "warn",
                )
                .await;
                return;
            }
            Err(e) => {
                preset_apply_audit(
                    state,
                    preset_id,
                    delegate_omni,
                    format!("catalog unreachable: {e}"),
                    "warn",
                )
                .await;
                return;
            }
        };

    // Persona: the SAME validation gate as the editor — nothing invalid enters
    // canonical. A repo bundle failing it is a build bug; loud, never partial.
    let persona_note = if let Err(e) = crate::persona::validate_persona_body(&bundle.soul_md) {
        tracing::error!(
            target: "agentkeys.daemon.ui_bridge",
            preset_id,
            error = %e,
            "preset SOUL.md failed the persona validation gate — repo-bundle bug"
        );
        format!("persona SKIPPED (bundle invalid: {e})")
    } else {
        match persona_commit(
            state,
            delegate_omni,
            &bundle.soul_md,
            "persona.preset",
            format!(
                "preset '{preset_id}' persona seeded at spawn for {}",
                normalize_omni_0x(delegate_omni).to_lowercase()
            ),
            sandbox_id,
        )
        .await
        {
            Ok(r) => format!("persona v{} (applied: {})", r.version, r.applied),
            Err((_, e)) => {
                tracing::warn!(
                    target: "agentkeys.daemon.ui_bridge",
                    preset_id,
                    "preset persona seed failed — {e}"
                );
                format!("persona seed FAILED: {e}")
            }
        }
    };

    // Skills → the sandbox skills dir. The bridge's `skills_written` response
    // key is the capability signal: absent = pre-#428 image, called out loud.
    let skills_note = if bundle.skills.is_empty() {
        "no skills in bundle".to_string()
    } else {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let mut skills = serde_json::Map::new();
        for doc in &bundle.skills {
            skills.insert(
                doc.filename.clone(),
                serde_json::Value::String(STANDARD.encode(doc.content.as_bytes())),
            );
        }
        let body = serde_json::json!({ "skills": skills, "restart": false });
        match sandbox_bridge_request_instanced(
            state,
            reqwest::Method::POST,
            "/v1/context/apply",
            Some(body),
            sandbox_id,
        )
        .await
        {
            Ok(v) => match v.get("skills_written").and_then(|s| s.as_array()) {
                Some(w) => format!("{} skills doc(s) distributed", w.len()),
                None => {
                    tracing::warn!(
                        target: "agentkeys.daemon.ui_bridge",
                        preset_id,
                        "bridge accepted the apply but returned no skills_written — the \
                         sandbox image predates #428 skills distribution; rebuild \
                         docker/hermes-sandbox"
                    );
                    "skills NOT distributed (pre-#428 sandbox image — rebuild required)".into()
                }
            },
            Err(e) if e.contains("files and/or skills") || e.contains("files must be") => {
                tracing::warn!(
                    target: "agentkeys.daemon.ui_bridge",
                    preset_id,
                    "bridge rejected the skills apply ({e}) — pre-#428 sandbox image; \
                     rebuild docker/hermes-sandbox"
                );
                "skills NOT distributed (pre-#428 sandbox image — rebuild required)".into()
            }
            Err(e) => {
                tracing::warn!(
                    target: "agentkeys.daemon.ui_bridge",
                    preset_id,
                    "skills distribution failed — {e}"
                );
                format!("skills distribution failed: {e}")
            }
        }
    };

    preset_apply_audit(
        state,
        preset_id,
        delegate_omni,
        format!("{persona_note}; {skills_note}"),
        "ok",
    )
    .await;
}

/// One audit-feed line per preset apply — the operator-visible record of what
/// the spawn actually distributed (or loudly failed to).
async fn preset_apply_audit(
    state: &SharedUiBridgeState,
    preset_id: &str,
    delegate_omni: &str,
    detail: String,
    sev: &str,
) {
    let evt = ApiAuditEvent {
        id: format!("e-preset-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "agent.preset_applied".into(),
        detail: format!(
            "preset '{preset_id}' → {}: {detail}",
            normalize_omni_0x(delegate_omni).to_lowercase()
        ),
        chip: "spawn".into(),
        sev: sev.into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(state, evt).await;
}

/// #248 — the Touch-ID-gated scope re-grant for an ALREADY-bound agent (the
/// permissions panel's commit). The browser stages the new namespace set, calls
/// `build` (→ broker assembles the `executeBatch([setScope])` UserOp + returns
/// the `userOpHash`), K11-signs it (Touch ID), then calls `submit`. The daemon
/// fills `operator_omni` from the master session (never the browser) and pins
/// the caps to 0 — the panel grants access, not payment limits.
#[derive(Debug, Deserialize)]
pub struct DaemonScopeBuildRequest {
    /// The agent's actor omni (`ApiActor.omni_hex`).
    pub actor_omni: String,
    /// FULL replacement service list (`memory:<ns>` canonical encoding);
    /// `setScope` is set-replace, so an empty list revokes every grant.
    pub services: Vec<String>,
    /// `ApiActor.scope_unknown_service_ids` echoed back — on-chain grants the
    /// panel can't name (e.g. `cred:<service>`) that must survive the replace.
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    pub read_only: bool,
}

/// POST /v1/scope/build — forward to the broker's `/v1/scope/build`, returning
/// the `userOpHash` the browser K11-signs. Body shape is crate-owned
/// (`agentkeys_backend_client::protocol::BuildScopeUserOpRequest`, #203).
async fn scope_build_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DaemonScopeBuildRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let (actor_omni, services) = (req.actor_omni.clone(), req.services.clone());
    let body = agentkeys_backend_client::protocol::BuildScopeUserOpRequest {
        operator_omni,
        actor_omni: req.actor_omni,
        services: req.services,
        preserve_service_ids: req.preserve_service_ids,
        read_only: req.read_only,
        max_per_call: "0".into(),
        max_per_period: "0".into(),
        max_total: "0".into(),
        period_seconds: 0,
    };
    let body = match serde_json::to_value(&body) {
        Ok(v) => v,
        Err(e) => {
            return pairing_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("scope build body: {e}"),
            )
        }
    };
    let (resp, parsed) = forward_to_broker_value(&broker, "/v1/scope/build", &j1, &body).await;
    if resp.status().is_success() {
        // #424 §1 — stash the readable grant NAMES keyed by the op hash; the
        // submit proxy consumes it on a confirmed commit to upsert the binding
        // manifest (the chain stores only keccak ids).
        if let Some(hash) = parsed
            .as_ref()
            .and_then(|v| v.get("user_op_hash"))
            .and_then(|v| v.as_str())
            .filter(|h| !h.is_empty())
        {
            state
                .scope_services_by_op_hash
                .write()
                .await
                .insert(hash.to_string(), (actor_omni, services));
        }
    }
    resp
}

/// POST /v1/scope/submit — forward the K11-signed setScope op to the broker's
/// `/v1/scope/submit` (the shared accept relay → EntryPoint.handleOps). On
/// success, un-latch the #233 sync so the next `list_actors` re-reads the grant
/// from chain (the mirror is what makes the committed change stick in the panel
/// instead of being reverted by a stale local map).
async fn scope_submit_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let (resp, parsed) = forward_to_broker_value(&broker, "/v1/scope/submit", &j1, &body).await;
    if resp.status().is_success() {
        invalidate_fleet_sync(&state);
        // #424 §1 — the commit landed: upsert the binding manifest with the
        // grant NAMES stashed at build time (keyed by the op hash), so a scope
        // re-grant / channel edit stays restart-durable, not RAM-only.
        if let Some((actor_omni, services)) = {
            let hash = parsed
                .as_ref()
                .and_then(|v| v.get("user_op_hash"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            state.scope_services_by_op_hash.write().await.remove(&hash)
        } {
            upsert_binding_manifest_entry(
                &state,
                BindingManifestEntry {
                    actor_omni,
                    device_key_hash: String::new(), // kept from the existing entry
                    label: String::new(),           // kept from the existing entry
                    kind: String::new(),            // kept from the existing entry
                    granted_service_names: services,
                    updated_at: now_unix(),
                    preset_id: None,      // kept from the existing entry (#427)
                    memory_ns: None,      // kept from the existing entry (#427)
                    archived_at: None,    // kept from the existing entry (#427)
                    resources_kept: None, // kept from the existing entry (#427)
                },
            )
            .await;
        }
        // #97: record the confirmed set-replace commit with the broker's real
        // receipts. The envelope (fetched by hash in the decode view) carries
        // the FULL replacement grant — incl. whether it was a revoke-all.
        let (tx_hash, audit_envelope_hashes) =
            parsed.as_ref().map(submit_receipts).unwrap_or((None, None));
        let evt = ApiAuditEvent {
            id: format!("e-scope-commit-{}", now_unix()),
            ts: now_ts_hms(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "scope.grant".into(),
            detail: format!(
                "setScope committed on chain (set-replace — full grant in the audit envelope){}",
                tx_hash
                    .as_deref()
                    .map(|h| format!(" · tx={h}"))
                    .unwrap_or_default()
            ),
            chip: "broker".into(),
            sev: "ok".into(),
            tx_hash,
            audit_envelope_hashes,
        };
        push_audit(&state, evt).await;
    }
    resp
}

/// The Touch-ID-gated agent **unpair** — the revoke sibling of the scope
/// proxies. `revokeAgentDevice` requires `msg.sender == operatorMasterWallet`,
/// so for an account-master operator the browser builds + K11-signs the
/// master-account UserOp; the legacy `heima-device-revoke.sh` EOA path reverts
/// `NotAuthorized` for those operators (real 2026-06-11 incident).
#[derive(Debug, Deserialize)]
pub struct DaemonRevokeBuildRequest {
    /// The agents' on-chain `SidecarRegistry` device key hashes
    /// (`ApiActor.device_key_hash`) — one for the single unpair, every paired
    /// agent for the #260 reset fleet revoke (ONE executeBatch, ONE Touch ID).
    pub device_key_hashes: Vec<String>,
}

/// POST /v1/revoke/build — forward to the broker's `/v1/revoke/build`, returning
/// the `userOpHash` the browser K11-signs. Body shape is crate-owned
/// (`agentkeys_backend_client::protocol::BuildRevokeUserOpRequest`, #203).
async fn revoke_build_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<DaemonRevokeBuildRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let (j1, operator_omni) = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => (s.j1.clone(), s.omni.clone()),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let body = agentkeys_backend_client::protocol::BuildRevokeUserOpRequest {
        operator_omni,
        device_key_hashes: req.device_key_hashes,
    };
    let body = match serde_json::to_value(&body) {
        Ok(v) => v,
        Err(e) => {
            return pairing_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("revoke build body: {e}"),
            )
        }
    };
    forward_to_broker(&broker, "/v1/revoke/build", &j1, &body).await
}

/// POST /v1/revoke/submit — forward the K11-signed revoke op to the broker's
/// `/v1/revoke/submit` (the shared accept relay). On success, un-latch the #233
/// sync so the next `list_actors` reconciles the revoked device from chain.
async fn revoke_submit_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => return pairing_err(StatusCode::FORBIDDEN, "no master session"),
    };
    let resp = forward_to_broker(&broker, "/v1/revoke/submit", &j1, &body).await;
    if resp.status().is_success() {
        invalidate_fleet_sync(&state);
    }
    resp
}

/// [`forward_to_broker`] that ALSO hands back the parsed success JSON, so the
/// submit proxies can read the #97 receipts (`tx_hash` +
/// `audit_envelope_hashes`) before re-wrapping the response for the browser.
/// POST `body` to `<broker><path>` with the master J1 bearer; return the broker's
/// status + parsed JSON (#278 D6 internal register-build forward). Unlike
/// [`forward_to_broker`] this is for INTERNAL callers (not an axum proxy), so it
/// yields a typed `(StatusCode, Value)` instead of a relayed `Response`.
async fn broker_post_json(
    broker: &str,
    path: &str,
    j1: &str,
    body: &serde_json::Value,
) -> Result<(StatusCode, serde_json::Value), String> {
    let url = format!("{}{}", broker.trim_end_matches('/'), path);
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(j1)
        .json(body)
        .send()
        .await
        .map_err(|e| format!("broker {path}: {e}"))?;
    let st = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let txt = resp.text().await.unwrap_or_default();
    let v =
        serde_json::from_str::<serde_json::Value>(&txt).unwrap_or(serde_json::Value::String(txt));
    Ok((st, v))
}

async fn forward_to_broker_value(
    broker: &str,
    path: &str,
    j1: &str,
    body: &serde_json::Value,
) -> (axum::response::Response, Option<serde_json::Value>) {
    let url = format!("{}{}", broker.trim_end_matches('/'), path);
    match reqwest::Client::new()
        .post(&url)
        .bearer_auth(j1)
        .json(body)
        .send()
        .await
    {
        Ok(resp) => {
            let st =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let txt = resp.text().await.unwrap_or_default();
            // Parse the body on BOTH success and error. Success callers read the
            // submit receipts from it; the #278 register-submit error path surfaces
            // the broker's REAL reason from it (e.g. "handleOps did not broadcast:
            // bundler eth_sendUserOperation: <reason>") instead of a generic
            // fallback — propagate the error through every layer, never swallow it.
            let parsed = serde_json::from_str::<serde_json::Value>(&txt).ok();
            let response = (
                st,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                txt,
            )
                .into_response();
            (response, parsed)
        }
        Err(e) => (
            pairing_err(StatusCode::BAD_GATEWAY, &format!("broker {path}: {e}")),
            None,
        ),
    }
}

/// Pull the #97 submit receipts out of a broker submit response: the confirmed
/// `tx_hash` + the `audit_envelope_hashes` the broker emitted for the landed
/// batch. Empty / missing values normalize to `None` (a `pending: true`
/// response carries neither).
fn submit_receipts(v: &serde_json::Value) -> (Option<String>, Option<Vec<String>>) {
    let tx_hash = v
        .get("tx_hash")
        .and_then(|t| t.as_str())
        .filter(|t| !t.is_empty())
        .map(str::to_string);
    let hashes = v
        .get("audit_envelope_hashes")
        .and_then(|h| h.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .filter(|h| !h.is_empty());
    (tx_hash, hashes)
}

// ── #418 WeChat gateway admin proxy ──────────────────────────────────────────
//
// Parent-control never talks to the gateway (or holds its admin bearer)
// directly: these thin forwards require the DAEMON's master session, then call
// the gateway's `/v1/gateway/admin/*` with the operator-configured bearer. The
// response passes through verbatim (one-owner shapes in `agentkeys-protocol`,
// ts-rs-exported for the frontend). The 60 s client timeout covers the
// gateway's ~35 s server-held login-status poll.

async fn forward_to_gateway(
    state: &SharedUiBridgeState,
    method: reqwest::Method,
    sub_path: &str,
    raw_query: Option<&str>,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    if state.onboarding_session.read().await.is_none() {
        return pairing_err(StatusCode::FORBIDDEN, "no master session");
    }
    let Some(gw) = state.weixin_gateway_url.clone() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway-not-configured — the daemon derives the gateway URL from its broker \
             (weixin.<zone>); point it at a deployed broker, or set AGENTKEYS_WORKER_WEIXIN_URL",
        );
    };
    let Some(admin) = state.weixin_admin_token.clone() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway-admin-not-configured — set AGENTKEYS_WEIXIN_ADMIN_TOKEN (from the broker's \
             weixin-secrets.env)",
        );
    };
    let mut url = format!("{gw}{sub_path}");
    if let Some(q) = raw_query.filter(|q| !q.is_empty()) {
        url.push('?');
        url.push_str(q);
    }
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, &url)
        .timeout(std::time::Duration::from_secs(60))
        .bearer_auth(admin);
    if let Some(b) = body {
        req = req.json(&b);
    }
    match req.send().await {
        Ok(resp) => {
            let st =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let txt = resp.text().await.unwrap_or_default();
            (
                st,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                txt,
            )
                .into_response()
        }
        Err(e) => pairing_err(StatusCode::BAD_GATEWAY, &format!("gateway {sub_path}: {e}")),
    }
}

async fn gateway_status_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/status",
        None,
        None,
    )
    .await
}

async fn gateway_login_start_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::POST,
        "/v1/gateway/admin/login/start",
        None,
        Some(serde_json::json!({})),
    )
    .await
}

async fn gateway_login_status_proxy(
    State(state): State<SharedUiBridgeState>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/login/status",
        q.as_deref(),
        None,
    )
    .await
}

async fn gateway_monitor_proxy(
    State(state): State<SharedUiBridgeState>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/monitor",
        q.as_deref(),
        None,
    )
    .await
}

async fn gateway_history_proxy(
    State(state): State<SharedUiBridgeState>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/history",
        q.as_deref(),
        None,
    )
    .await
}

async fn gateway_activity_proxy(
    State(state): State<SharedUiBridgeState>,
    axum::extract::RawQuery(q): axum::extract::RawQuery,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/activity",
        q.as_deref(),
        None,
    )
    .await
}

async fn gateway_login_verify_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::POST,
        "/v1/gateway/admin/login/verify",
        None,
        Some(body),
    )
    .await
}

async fn gateway_login_disconnect_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::POST,
        "/v1/gateway/admin/login/disconnect",
        None,
        None,
    )
    .await
}

/// #424 §2 — forward a REGISTRY-MUTATING gateway admin call, then write-through
/// the gateway's full contact registry into the Config-class doc so it survives
/// a gateway host rebuild. Best-effort: the gateway mutation already landed, so
/// a sync failure WARNS loudly (the next successful mutation re-syncs the full
/// snapshot) but never fails the request.
async fn forward_gateway_mutation(
    state: &SharedUiBridgeState,
    sub_path: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let resp = forward_to_gateway(state, reqwest::Method::POST, sub_path, None, Some(body)).await;
    if resp.status().is_success() {
        sync_gateway_registry_to_config(state).await;
    }
    resp
}

async fn gateway_bind_invite_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_gateway_mutation(&state, "/v1/gateway/admin/bind/invite", body).await
}

async fn gateway_bind_pending_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/bind/pending",
        None,
        None,
    )
    .await
}

async fn gateway_bind_reject_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_gateway_mutation(&state, "/v1/gateway/admin/bind/reject", body).await
}

async fn gateway_bind_approve_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_gateway_mutation(&state, "/v1/gateway/admin/bind/approve", body).await
}

async fn gateway_contacts_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    // #424 §2 — once per process, reconcile the gateway's local registry with
    // the durable Config-class doc (migrate a legacy on-host file UP; restore a
    // rebuilt/empty gateway DOWN) before serving the contacts view.
    reconcile_gateway_registry(&state).await;
    forward_to_gateway(
        &state,
        reqwest::Method::GET,
        "/v1/gateway/admin/contacts",
        None,
        None,
    )
    .await
}

async fn gateway_contacts_update_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_gateway_mutation(&state, "/v1/gateway/admin/contacts/update", body).await
}

async fn gateway_contacts_revoke_proxy(
    State(state): State<SharedUiBridgeState>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    forward_gateway_mutation(&state, "/v1/gateway/admin/contacts/revoke", body).await
}

// ── #424 §2 — gateway contact-registry durability (Config-class doc) ─────────

/// Raw admin-bearer JSON call to the gateway (the sync/reconcile plumbing —
/// distinct from [`forward_to_gateway`], which proxies a browser request).
async fn gateway_admin_call(
    state: &UiBridgeState,
    method: reqwest::Method,
    sub_path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let gw = state
        .weixin_gateway_url
        .clone()
        .ok_or("gateway-not-configured")?;
    let admin = state
        .weixin_admin_token
        .clone()
        .ok_or("gateway-admin-not-configured")?;
    let client = reqwest::Client::new();
    let mut req = client
        .request(method, format!("{gw}{sub_path}"))
        .timeout(std::time::Duration::from_secs(15))
        .bearer_auth(admin);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("gateway {sub_path}: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("gateway {sub_path} {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("gateway {sub_path} parse: {e}"))
}

/// A gateway `ContactRegistry` JSON with no bound contacts, no open invites and
/// no pending claims — the "fresh host" shape the restore path may overwrite.
fn gateway_registry_is_empty(reg: &serde_json::Value) -> bool {
    ["bound", "invites", "pending"].iter().all(|k| {
        reg.get(*k)
            .and_then(|v| v.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(true)
    })
}

/// Export the gateway's full registry and store it as the Config-class doc.
/// Best-effort at every call site (the gateway mutation already landed): a
/// failure WARNS loudly; the next successful mutation re-syncs the snapshot.
async fn sync_gateway_registry_to_config(state: &UiBridgeState) {
    let reg = match gateway_admin_call(
        state,
        reqwest::Method::GET,
        "/v1/gateway/admin/registry/export",
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                "gateway registry export failed — contact registry NOT synced to the \
                 durable config doc ({e}); next successful contact mutation retries"
            );
            return;
        }
    };
    match real_config_ctx(state).await {
        Ok(Some(ctx)) => {
            let bytes = match serde_json::to_vec(&reg) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        target: "agentkeys.daemon.ui_bridge",
                        "gateway registry serialize failed: {e}"
                    );
                    return;
                }
            };
            let client = reqwest::Client::new();
            match config_store_doc(&client, &ctx, GATEWAY_CONTACTS_SERVICE, &bytes).await {
                Ok(()) => tracing::info!(
                    target: "agentkeys.daemon.ui_bridge",
                    "gateway contact registry synced to the durable config doc"
                ),
                Err(e) => tracing::warn!(
                    target: "agentkeys.daemon.ui_bridge",
                    "gateway contact registry config store failed — NOT durable ({e}); \
                     next successful contact mutation retries"
                ),
            }
        }
        Ok(None) => tracing::debug!(
            target: "agentkeys.daemon.ui_bridge",
            "Config unconfigured (dev/no-infra) — gateway registry stays gateway-local"
        ),
        Err(e) => tracing::warn!(
            target: "agentkeys.daemon.ui_bridge",
            "config ctx unavailable — gateway contact registry NOT synced ({e})"
        ),
    }
}

/// Once per daemon process (latched): reconcile the gateway's local registry
/// with the durable Config-class doc.
///
/// - gateway NON-empty → store the snapshot up (the one-time migration of a
///   legacy on-host file, and the drift heal; idempotent — full-snapshot PUT).
/// - gateway EMPTY + durable doc non-empty → import the doc back into the
///   gateway (the host-rebuild restore; `force:false`, so a racing bind on the
///   gateway wins and the import refuses rather than clobbers).
/// - both empty / Config unconfigured → nothing.
///
/// Transient failures un-latch so a later contacts read retries.
async fn reconcile_gateway_registry(state: &UiBridgeState) {
    use std::sync::atomic::Ordering;
    if state.gateway_registry_synced.swap(true, Ordering::SeqCst) {
        return;
    }
    let unlatch = || state.gateway_registry_synced.store(false, Ordering::SeqCst);
    let gw_reg = match gateway_admin_call(
        state,
        reqwest::Method::GET,
        "/v1/gateway/admin/registry/export",
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                target: "agentkeys.daemon.ui_bridge",
                "gateway registry reconcile skipped (export: {e})"
            );
            unlatch();
            return;
        }
    };
    if !gateway_registry_is_empty(&gw_reg) {
        sync_gateway_registry_to_config(state).await;
        return;
    }
    // Gateway is EMPTY — a fresh/rebuilt host. Restore the durable copy, if any.
    let doc = match real_config_ctx(state).await {
        Ok(Some(ctx)) => {
            let client = reqwest::Client::new();
            match config_fetch_doc(&client, &ctx, GATEWAY_CONTACTS_SERVICE).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::warn!(
                        target: "agentkeys.daemon.ui_bridge",
                        "gateway registry restore skipped (config fetch: {e})"
                    );
                    unlatch();
                    return;
                }
            }
        }
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(
                target: "agentkeys.daemon.ui_bridge",
                "gateway registry reconcile skipped (config ctx: {e})"
            );
            unlatch();
            return;
        }
    };
    let Some(bytes) = doc else {
        return; // nothing durable yet — a genuinely fresh household
    };
    let durable: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                "durable gateway registry doc unparsable — restore skipped ({e})"
            );
            return;
        }
    };
    if gateway_registry_is_empty(&durable) {
        return;
    }
    match gateway_admin_call(
        state,
        reqwest::Method::POST,
        "/v1/gateway/admin/registry/import",
        Some(serde_json::json!({ "registry": durable, "force": false })),
    )
    .await
    {
        Ok(counts) => tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            "gateway contact registry RESTORED from the durable config doc: {counts}"
        ),
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                "gateway contact registry restore FAILED ({e})"
            );
            unlatch();
        }
    }
}

/// POST `body` to `<broker><path>` with the master J1 bearer; relay the broker's
/// status + JSON body back to the browser verbatim.
async fn forward_to_broker(
    broker: &str,
    path: &str,
    j1: &str,
    body: &serde_json::Value,
) -> axum::response::Response {
    let url = format!("{}{}", broker.trim_end_matches('/'), path);
    match reqwest::Client::new()
        .post(&url)
        .bearer_auth(j1)
        .json(body)
        .send()
        .await
    {
        Ok(resp) => {
            let st =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let txt = resp.text().await.unwrap_or_default();
            (
                st,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                txt,
            )
                .into_response()
        }
        Err(e) => pairing_err(StatusCode::BAD_GATEWAY, &format!("broker {path}: {e}")),
    }
}

/// GET-forward to an UNAUTHENTICATED broker route (#428 preset catalog —
/// static compiled-in product content; the broker side documents why no
/// bearer). The web app only ever talks to the daemon, so this is its window.
async fn forward_broker_get(broker: &str, path: &str) -> axum::response::Response {
    let url = format!("{}{}", broker.trim_end_matches('/'), path);
    match reqwest::Client::new().get(&url).send().await {
        Ok(resp) => {
            let st =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let txt = resp.text().await.unwrap_or_default();
            (
                st,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                txt,
            )
                .into_response()
        }
        Err(e) => pairing_err(StatusCode::BAD_GATEWAY, &format!("broker {path}: {e}")),
    }
}

/// GET /v1/presets — proxy the #428 broker preset catalog for the web app.
async fn presets_catalog_proxy(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    forward_broker_get(&broker, "/v1/presets").await
}

/// GET /v1/presets/:id — proxy one full preset bundle.
async fn preset_bundle_proxy(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.clone() else {
        return pairing_err(StatusCode::SERVICE_UNAVAILABLE, "no broker configured");
    };
    // The id charset is the channel-id/label discipline — reject anything that
    // couldn't be a bundle id before it reaches a URL path.
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || id.is_empty()
        || id.len() > 48
    {
        return pairing_err(StatusCode::BAD_REQUEST, "invalid preset id");
    }
    forward_broker_get(&broker, &format!("/v1/presets/{id}")).await
}

/// POST /v1/agent/pairing/register — the master approves a claimed agent: submit
/// `registerAgentDevice` on chain for its sandbox-generated device key, then ack
/// the broker so it clears from pending (#214, §10.2 P.2). The device fields come
/// from the broker's AUTHORITATIVE pending binding (never the browser). Shells out
/// to `heima-agent-create.sh --from-pubkey` (the sibling of the master register
/// script), mirroring `register_master_device`. The Touch-ID scope grant is the
/// separate `/v1/actors/:id/scope/grant` step (P.3).
async fn register_pairing(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<RegisterPairingRequest>,
) -> axum::response::Response {
    let Some(broker) = state.broker_url.as_deref() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no broker configured (--broker-url)",
        );
    };
    let j1 = match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => s.j1.clone(),
        _ => {
            return pairing_err(
                StatusCode::FORBIDDEN,
                "no master session — verify email + register the master first",
            )
        }
    };
    // The agent-create script is the sibling of the master register script (both
    // live in scripts/); reuse that config rather than a second flag.
    let Some(master_script) = state.register_master_script.clone() else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "on-chain register not configured (--register-master-script) — cannot register the agent device",
        );
    };
    // `heima-agent-create.sh` canonically lives in `<repo>/scripts/`, while the
    // master register script (`--register-master-script`) may be in
    // `<repo>/e2e/scripts/` (dev.sh) — so it is NOT always a sibling. Try the
    // sibling first (co-located case), then `<repo>/scripts/` derived from the
    // master script path. (#214 register-pairing path-mismatch fix — a missing
    // script otherwise surfaced as a confusing 502 on `accept pairing`.)
    let master_path = std::path::Path::new(&master_script);
    let agent_script_candidates = [
        master_path
            .parent()
            .map(|d| d.join("heima-agent-create.sh")),
        master_path
            .parent()
            .and_then(|d| d.parent())
            .and_then(|d| d.parent())
            .map(|repo| repo.join("scripts").join("heima-agent-create.sh")),
    ];
    let Some(agent_script) = agent_script_candidates
        .into_iter()
        .flatten()
        .find(|p| p.exists())
    else {
        return pairing_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "heima-agent-create.sh not found (looked next to --register-master-script and in <repo>/scripts/)",
        );
    };
    // Pull the authoritative binding from the broker (device fields, never the UI).
    let bindings = match agentkeys_cli::agent_admin::agent_pending_value(broker, &j1).await {
        Ok(v) => v,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("broker pending-bindings: {e:#}"),
            )
        }
    };
    let row = bindings
        .get("pending")
        .and_then(|p| p.as_array())
        .and_then(|rows| {
            rows.iter()
                .find(|r| {
                    r.get("request_id").and_then(|v| v.as_str()) == Some(req.request_id.as_str())
                })
                .cloned()
        });
    let Some(row) = row else {
        return pairing_err(
            StatusCode::NOT_FOUND,
            "no pending binding for that request_id (claim it first, or it was already registered)",
        );
    };
    let field = |k: &str| {
        row.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let label = field("label");
    // The binding's `device_pubkey` holds the agent's EVM address (§10.2).
    let agent_address = field("device_pubkey");
    let actor_omni = field("child_omni");
    let device_key_hash = field("device_key_hash");
    let pop_sig = field("pop_sig");
    if label.is_empty()
        || agent_address.is_empty()
        || actor_omni.is_empty()
        || device_key_hash.is_empty()
        || pop_sig.is_empty()
    {
        return pairing_err(
            StatusCode::BAD_GATEWAY,
            "pending binding is missing device fields (label/address/omni/key-hash/pop-sig)",
        );
    }
    let tx = match register_agent_device(
        &agent_script.to_string_lossy(),
        &label,
        &agent_address,
        &actor_omni,
        &device_key_hash,
        &pop_sig,
    )
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            return pairing_err(
                StatusCode::BAD_GATEWAY,
                &format!("registerAgentDevice: {e}"),
            )
        }
    };
    // Clear it from the broker's pending list (best-effort — the chain write is
    // the binding act; a failed ack just leaves a stale pending row).
    if let Err(e) = agentkeys_cli::agent_admin::agent_ack(broker, &req.request_id, &j1).await {
        tracing::warn!("ui-bridge: registered agent but broker ack failed: {e:#}");
    }
    tracing::info!(
        target: "agentkeys.daemon.ui_bridge",
        label = %label,
        actor_omni = %actor_omni,
        tx = tx.as_deref().unwrap_or("(already-registered)"),
        "#214: agent device registered on chain (web pairing)"
    );
    // Surface the freshly-registered agent in the web UI (state.actors) so it
    // appears in the devices view + becomes targetable by the existing scope-grant
    // flow (P.3, /v1/actors/:id/scope/grant). Keyed by `agent-<label>`, mirroring
    // the master actor's in-memory model (chain-backed reload is a separate concern).
    let omni_hex = if actor_omni.starts_with("0x") {
        actor_omni.clone()
    } else {
        format!("0x{actor_omni}")
    };
    let agent_actor = ApiActor {
        id: format!("agent-{label}"),
        omni: omni_hex.clone(),
        omni_hex,
        label: label.clone(),
        role: "agent".into(),
        parent: Some("master".into()),
        derivation: format!("//{label}"),
        device: "sandbox device (§10.2)".into(),
        device_pubkey: agent_address.clone(),
        last_active: "just paired".into(),
        status: "ok".into(),
        vendor: String::new(),
        k11: false,
        device_key_hash: Some(if device_key_hash.starts_with("0x") {
            device_key_hash.clone()
        } else {
            format!("0x{device_key_hash}")
        }),
        scope: None,
        scope_unknown_service_ids: None,
        payment_cap: None,
        time_window: None,
        services: None,
        account_address: None,
        account_type: None,
        preset_id: None,
        memory_ns: None,
    };
    state
        .actors
        .write()
        .await
        .insert(agent_actor.id.clone(), agent_actor);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "label": label, "actor_omni": actor_omni, "tx_hash": tx })),
    )
        .into_response()
}

/// Shell out to `heima-agent-create.sh --from-pubkey` to submit `registerAgentDevice`
/// for a SANDBOX-generated device key (the master never holds the agent key).
/// Mirrors `register_master_device`. Returns the tx hash (None on idempotent skip).
async fn register_agent_device(
    script: &str,
    label: &str,
    agent_address: &str,
    actor_omni: &str,
    device_key_hash: &str,
    pop_sig: &str,
) -> Result<Option<String>, String> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .arg("--label")
        .arg(label)
        .arg("--agent-address")
        .arg(agent_address)
        .arg("--actor-omni")
        .arg(actor_omni)
        .arg("--device-key-hash")
        .arg(device_key_hash)
        .arg("--pop-sig")
        .arg(pop_sig)
        .output()
        .await
        .map_err(|e| format!("spawn {script}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr.lines().rev().take(6).collect();
        lines.reverse();
        return Err(format!(
            "heima-agent-create.sh exited {}: {}",
            output.status,
            lines.join("\n")
        ));
    }
    // The script logs to stderr + prints a final JSON line to stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let tx = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v.get("tx_hash").and_then(|t| t.as_str()).map(String::from));
    Ok(tx)
}

/// Resolve a `<repo>/scripts/<name>` helper the same way `register_pairing` finds
/// `heima-agent-create.sh`: a sibling of the master register script first
/// (co-located dev case), then `<repo>/scripts/<name>` derived from it.
fn resolve_repo_script(master_script: &str, name: &str) -> Option<std::path::PathBuf> {
    let p = std::path::Path::new(master_script);
    [
        p.parent().map(|d| d.join(name)),
        p.parent()
            .and_then(|d| d.parent())
            .and_then(|d| d.parent())
            .map(|repo| repo.join("scripts").join(name)),
    ]
    .into_iter()
    .flatten()
    .find(|c| c.exists())
}

/// Shell out to `heima-device-revoke.sh --agent <label>` to submit
/// `revokeAgentDevice` on chain (the script reads `~/.agentkeys/agents/<label>.json`
/// and derives the device-key-hash itself). Agent-tier revocation needs no K11; the
/// script is idempotent (skips when already revoked). Returns the tx hash (None on
/// idempotent skip).
async fn revoke_agent_device(
    script: &std::path::Path,
    label: &str,
) -> Result<Option<String>, String> {
    revoke_agent_device_args(script, "--agent", label.trim_end_matches(" (revoked)")).await
}

/// Like [`revoke_agent_device`] but keyed on the on-chain device key hash —
/// the #233/#243 path for chain-reconstructed actors that never had a
/// `~/.agentkeys/agents/<label>.json` record on this machine.
async fn revoke_agent_device_by_hash(
    script: &std::path::Path,
    device_key_hash: &str,
) -> Result<Option<String>, String> {
    revoke_agent_device_args(script, "--device-key-hash", device_key_hash).await
}

async fn revoke_agent_device_args(
    script: &std::path::Path,
    flag: &str,
    value: &str,
) -> Result<Option<String>, String> {
    let output = tokio::process::Command::new("bash")
        .arg(script)
        .arg(flag)
        .arg(value)
        .output()
        .await
        .map_err(|e| format!("spawn heima-device-revoke.sh: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr.lines().rev().take(6).collect();
        lines.reverse();
        return Err(format!(
            "heima-device-revoke.sh exited {}: {}",
            output.status,
            lines.join("\n")
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let tx = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .and_then(|v| v.get("tx_hash").and_then(|t| t.as_str()).map(String::from));
    Ok(tx)
}

/// Shell out to `heima-reset-master.sh --operator-omni <omni>` to clear the
/// operator's ON-CHAIN `operatorMasterWallet` binding via the registry deployer
/// (the owner-gated `resetMaster`). Without this the local reset alone cannot let
/// the operator re-onboard: `registerFirstMasterDevice` is first-master-only, so
/// the immutable binding would keep a fresh passkey from re-binding and accept
/// would keep failing SIG_VALIDATION (#225 E7). Resolves the sibling script the
/// same way agent revoke does. Returns the parsed JSON (`{ok, tx_hash, …}` or
/// `{skipped:"already-unbound", …}`) or an error string the caller surfaces.
async fn reset_master_onchain(
    master_script: &str,
    operator_omni: &str,
) -> Result<serde_json::Value, String> {
    let script = resolve_repo_script(master_script, "heima-reset-master.sh")
        .ok_or_else(|| "heima-reset-master.sh not found next to the register script".to_string())?;
    let output = tokio::process::Command::new("bash")
        .arg(&script)
        .arg("--operator-omni")
        .arg(operator_omni)
        .output()
        .await
        .map_err(|e| format!("spawn heima-reset-master.sh: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr.lines().rev().take(8).collect();
        lines.reverse();
        return Err(format!(
            "heima-reset-master.sh exited {}: {}",
            output.status,
            lines.join("\n")
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| format!("reset script produced no JSON on stdout: {stdout}"))?;
    serde_json::from_str(json_line.trim()).map_err(|e| format!("reset JSON parse: {e}"))
}

async fn list_master_memory(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    match resolve_categories(&state).await {
        Ok(categories) => (
            StatusCode::OK,
            Json(serde_json::json!({ "categories": categories })),
        )
            .into_response(),
        Err(reason) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": reason })),
        )
            .into_response(),
    }
}

/// Resolve the category set. Cache fallback is returned ONLY for the two benign
/// cases — Config unconfigured, or the taxonomy object confirmed missing (404 /
/// never planted). Every OTHER Config failure (partial config, cap-mint/STS,
/// worker 5xx, decrypt/parse) is propagated as `Err` so the list 502s instead of
/// silently masking it as an empty store (codex finding 2).
async fn resolve_categories(state: &SharedUiBridgeState) -> Result<Vec<MemoryCategory>, String> {
    match real_config_ctx(state).await {
        Ok(Some(ctx)) => {
            let client = reqwest::Client::new();
            match config_fetch_taxonomy(&client, &ctx).await {
                Ok(Some(tax)) if !tax.categories.is_empty() => Ok(tax.categories),
                // Present-but-empty (unusual) or confirmed-missing taxonomy →
                // fallback is legitimate (nothing durable to list).
                Ok(_) => Ok(fallback_categories(state).await),
                // A configured-but-broken Config store is a HARD error (502), never
                // masked behind in-memory data or an empty list (#201 finding-2):
                // the operator must see + fix it. Real data or a loud failure.
                Err(e) => Err(format!("config taxonomy unavailable: {e}")),
            }
        }
        Ok(None) => Ok(fallback_categories(state).await), // Config not configured
        Err(e) => Err(format!("config not ready: {e}")),  // partial config / no session
    }
}

/// Categories to show when no durable taxonomy is available — the union of the
/// authored in-memory taxonomy (`init`, #207 item 1A) and the cache-derived
/// namespaces (planted memory). Used as the dev/no-infra path and as the
/// real-path fallback when the durable object is missing/empty, so an authored
/// preset is visible even before any memory is planted.
async fn fallback_categories(state: &SharedUiBridgeState) -> Vec<MemoryCategory> {
    let cache_cats = categories_from_cache(state).await;
    match state.authored_taxonomy.read().await.clone() {
        Some(tax) => merge_categories(tax.categories, &cache_cats),
        None => cache_cats,
    }
}

/// Derive categories from the distinct namespaces present in the in-memory
/// cache (the dev/no-infra path + the post-restart fallback before the durable
/// taxonomy is re-read). Labels are title-cased from the namespace.
async fn categories_from_cache(state: &SharedUiBridgeState) -> Vec<MemoryCategory> {
    let guard = state.master_memory.read().await;
    let mut seen = std::collections::BTreeSet::new();
    for e in guard.values() {
        seen.insert(e.ns.clone());
    }
    seen.into_iter()
        .map(|ns| MemoryCategory {
            label: label_for_ns(&ns),
            ns,
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct MemoryEntryQuery {
    pub ns: String,
    #[serde(default)]
    pub key: Option<String>,
}

/// `GET /v1/master/memory/entry?ns=<ns>[&key=<key>]` → the entries in one
/// namespace, decrypted ON DEMAND (#201 Phase 4 lazy detail). Real chain:
/// memory-get(`memory:<ns>`) → decrypt → parse the JSON array. Fallback:
/// filter the in-memory cache. `&key=` narrows to a single entry.
async fn get_master_memory_entry(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<MemoryEntryQuery>,
) -> axum::response::Response {
    match get_master_memory_entry_inner(&state, &q).await {
        Ok(entries) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ns": q.ns, "entries": entries })),
        )
            .into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn get_master_memory_entry_inner(
    state: &SharedUiBridgeState,
    q: &MemoryEntryQuery,
) -> Result<Vec<ApiMemoryEntry>, (StatusCode, String)> {
    let ctx = real_memory_ctx(state)
        .await
        .map_err(|reason| (StatusCode::CONFLICT, reason))?;
    if let Some(ctx) = ctx {
        let client = reqwest::Client::new();
        let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
            &ctx.broker,
            &ctx.j1,
            &ctx.role_arn,
            &ctx.region,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay: {e}")))?;
        // Ok(None) → the namespace has no durable blob (nothing to show); a real
        // worker error surfaces as 502 (not an empty list masking a failure).
        let stored = memory_get_ns_real(&client, &ctx, &creds, &q.ns)
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, e))?
            .unwrap_or_default();
        Ok(stored
            .into_iter()
            .filter(|s| q.key.as_deref().is_none_or(|k| k == s.key))
            .map(|s| ApiMemoryEntry::from_stored(&q.ns, s))
            .collect())
    } else {
        let guard = state.master_memory.read().await;
        let mut entries: Vec<ApiMemoryEntry> = guard
            .values()
            .filter(|e| e.ns == q.ns && q.key.as_deref().is_none_or(|k| k == e.key))
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(entries)
    }
}

// ─── W3: real memory chain (cap-mint → STS relay → worker → S3) ─────────────
//
// When the daemon has --memory-url + --memory-role-arn + --master-device-key-hash
// AND a master onboarding session, the master plants its OWN memory under its
// actor_omni (operator == actor == O_master) via the same chain the MCP
// http_backend + suite-5-wire-real use. Otherwise plant falls back to the
// in-memory store. Per-actor by construction (cap-mint binds device.actor_omni
// == req.actor_omni); see docs/plan/web-flow/w3-real-memory.md §1.

/// The session-scoped coordinates shared by every real-chain worker call
/// (memory + config): the broker, the master J1, the (normalized) master omni,
/// the on-chain device hash, and the region. Resolved once; the per-data-class
/// contexts add the worker URL + IAM role on top.
struct SessionCoords {
    broker: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// Resolve the master session coordinates or fail loud (issue #90 discipline):
/// a missing broker / unregistered device / absent session is an `Err`, never a
/// silent degrade. Shared by `real_memory_ctx` + `real_config_ctx`.
async fn resolve_session_coords(state: &UiBridgeState) -> Result<SessionCoords, String> {
    let broker = state
        .broker_url
        .clone()
        .ok_or("real chain: worker URL set but --broker-url missing")?;
    // Resolve the live session FIRST so the error can distinguish three cases
    // (issue #220 — the old "master device not registered on chain yet" string was
    // MISLEADING: it meant "not in daemon memory", not "not on chain"):
    //   - no live session but coords ARE persisted → the J1 expired; one passkey
    //     re-auth restores it (NOT a full re-onboarding);
    //   - no session and nothing persisted → genuinely not onboarded;
    //   - session present but identity-only → managed-wallet attestation skipped.
    let session = match state.onboarding_session.read().await.clone() {
        Some(s) => s,
        None => {
            if state.master_session.read().await.is_some() {
                return Err("real chain: master session expired — re-authenticate \
                    (one passkey prompt) to restore it (no re-onboarding needed)"
                    .into());
            }
            return Err("real chain: no local master session — complete onboarding first".into());
        }
    };
    if session.omni.is_empty() || session.j1.is_empty() {
        return Err("real chain: master session is identity-only (no EVM omni/J1)".into());
    }
    // The broker cap-mint input-validates that operator_omni/actor_omni start with
    // 0x, but the onboarding session stores the omni bare. Normalize via the ONE
    // shared normalizer (issue #203) so every worker call (memory + config) sends
    // a 0x-prefixed omni and this can't drift from the cap-mint body the
    // MCP/harness paths send (the broker normalize_hex32's it either way).
    let omni = agentkeys_backend_client::normalize_omni_0x(&session.omni);
    // device_key_hash resolution, in precedence order:
    //   1. the K11-finish register result (issue #196) — the device actually on
    //      chain under this session omni;
    //   2. the --master-device-key-hash CLI flag (pre-registered device / tests);
    //   3. derive keccak(operator_omni) — the deterministic SidecarRegistry key
    //      (issue #220), so a restart needs neither a cached register nor the flag.
    //      The on-chain binding is the source of truth; this reproduces its key.
    let device_key_hash =
        match state.registered_master.read().await.as_ref() {
            Some(rm) => rm.device_key_hash.clone(),
            None => match state.master_device_key_hash.clone() {
                Some(h) => h,
                None => agentkeys_core::device_crypto::device_key_hash_from_omni(&omni).map_err(
                    |e| format!("real chain: cannot derive master device hash from omni: {e}"),
                )?,
            },
        };
    Ok(SessionCoords {
        broker,
        region: state.region.clone(),
        j1: session.j1,
        omni,
        device_key_hash,
    })
}

struct RealMemoryCtx {
    broker: String,
    memory_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// `Ok(None)` → real chain not configured (in-memory fallback). `Ok(Some)` →
/// fully configured + a master session present. `Err` → configured but a
/// required piece is missing (partial config / not logged in) — fail loud
/// rather than silently degrade per-actor isolation (issue #90 discipline).
async fn real_memory_ctx(state: &UiBridgeState) -> Result<Option<RealMemoryCtx>, String> {
    let Some(memory_url) = state.memory_url.clone() else {
        return Ok(None);
    };
    let role_arn = state
        .memory_role_arn
        .clone()
        .ok_or("real memory: --memory-url set but MEMORY_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealMemoryCtx {
        broker: c.broker,
        memory_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
    }))
}

struct RealConfigCtx {
    broker: String,
    config_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
    /// Signer base URL (#372 item 2): the taxonomy is CLIENT-encrypted under
    /// the signer-derived per-actor KEK (v3 envelopes) before it reaches the
    /// config worker. `None` fails LOUD at store/fetch time — never a silent
    /// fallback to worker-side plaintext.
    signer_url: Option<String>,
}

/// Same `Ok(None)`/`Ok(Some)`/`Err` contract as `real_memory_ctx`, gated on
/// `config_url` (#201 Config data class). When `None`, the taxonomy lives only
/// in the in-memory fallback and the list derives categories from the cache.
async fn real_config_ctx(state: &UiBridgeState) -> Result<Option<RealConfigCtx>, String> {
    let Some(config_url) = state.config_url.clone() else {
        return Ok(None);
    };
    let role_arn = state
        .config_role_arn
        .clone()
        .ok_or("real config: --config-url set but CONFIG_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealConfigCtx {
        broker: c.broker,
        config_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
        signer_url: state.signer_url.clone(),
    }))
}

/// Derive the per-(actor, service) config KEK via the signer (#372 item 2 —
/// the vault's `agentkeys.kek.v1` construction, `agentkeys-core::kek`). The
/// session J1 authenticates the `/dev/sign-message` call (the signer-only
/// listener requires a broker-session bearer, issue #74). Fails loud when the
/// signer is unconfigured — config confidentiality now DEPENDS on it.
async fn derive_config_kek(ctx: &RealConfigCtx, service: &str) -> Result<[u8; 32], String> {
    let signer_url = ctx.signer_url.as_deref().ok_or(
        "config v3: --signer-url / AGENTKEYS_SIGNER_URL missing — the taxonomy is \
         client-encrypted under the signer-derived per-actor KEK (#372); configure the signer",
    )?;
    let omni_no0x = ctx.omni.trim_start_matches("0x").to_lowercase();
    let signer = agentkeys_core::signer_client::HttpSignerClient::new(signer_url)
        .with_session_jwt(ctx.j1.clone());
    // Identity segment = the 0x-prefixed lowercase actor omni — the same
    // identity the S3 key + v3 AAD bind (config is master-self: actor == operator).
    agentkeys_core::kek::derive_kek_via_signer(
        &signer,
        &omni_no0x,
        &format!("0x{omni_no0x}"),
        service,
    )
    .await
    .map_err(|e| format!("config KEK derivation via signer: {e}"))
}

/// Mint a master-self cap for the given broker route (`memory-put` /
/// `memory-get` / `config-store` / `config-fetch`) and `service` string.
/// operator == actor == O_master, so the broker skips the on-chain scope check
/// (#195). Returns the raw cap JSON the worker re-verifies.
///
/// Routes through the shared `agentkeys-backend-client` (issue #203): the
/// cap-mint body IS the crate's `BrokerCapRequest`, so the daemon's cap-mint —
/// for memory AND the #201 config data class — can't drift its shape or omni
/// from the agent/MCP path (the #200 bug locus). Worker put/get bodies use the
/// crate's body types too (see callers); the raw worker POST stays here to reuse
/// the once-minted STS creds across namespaces.
async fn mint_master_cap(
    broker: &str,
    j1: &str,
    omni: &str,
    device_key_hash: &str,
    route: &str,
    service: &str,
) -> Result<agentkeys_backend_client::CapToken, String> {
    use agentkeys_backend_client::{BackendClient, CapMintOp, CapMintRequest};
    let op = match route {
        "memory-put" => CapMintOp::MemoryPut,
        "memory-get" => CapMintOp::MemoryGet,
        "config-store" => CapMintOp::ConfigStore,
        "config-fetch" => CapMintOp::ConfigFetch,
        "cred-store" => CapMintOp::CredStore,
        "cred-fetch" => CapMintOp::CredFetch,
        other => return Err(format!("mint_master_cap: unknown cap route {other}")),
    };
    let mut client = BackendClient::new(
        Some(broker.to_string()),
        None,
        None,
        None,
        None,
        None,
        None,
        String::new(),
    );
    // K10 cap-mint proof-of-possession (issue #76). Sign the master-self cap with
    // the master's K10 (the same owner-only file the daemon loaded at startup)
    // WHEN it's registered + present, so a compromised broker can't mint a usable
    // master cap. Graceful during rollout: when no K10 is available (a master
    // before its K10 is registered), mint without a PoP — the worker accepts it
    // unless AGENTKEYS_WORKER_REQUIRE_CAP_POP=1.
    if let Some(dk) = agentkeys_core::device_crypto::load_device_key_from_env() {
        client = client.with_device_key(std::sync::Arc::new(dk));
    }
    client
        .cap_mint(
            op,
            CapMintRequest {
                operator_omni: omni.to_string(),
                actor_omni: omni.to_string(),
                service: service.to_string(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            j1,
        )
        .await
        .map_err(|e| format!("cap-mint({route}): {e}"))
}

/// Per-namespace memory-put (#201 Phase 4): cap-mint(`memory:<ns>`) → worker
/// `/v1/memory/put` with the JSON array as plaintext. STS creds are minted once
/// by the caller and reused across namespaces. Returns the worker's S3 key.
async fn memory_put_ns_real(
    client: &reqwest::Client,
    ctx: &RealMemoryCtx,
    creds: &agentkeys_provisioner::AwsTempCreds,
    ns: &str,
    entries: &[StoredMemoryEntry],
) -> Result<String, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "memory-put",
        &format!("memory:{ns}"),
    )
    .await?;
    let plaintext = serde_json::to_vec(entries).map_err(|e| format!("ns array serialize: {e}"))?;
    let put_resp = client
        .post(format!("{}/v1/memory/put", ctx.memory_url))
        .header("x-aws-access-key-id", &creds.access_key_id)
        .header("x-aws-secret-access-key", &creds.secret_access_key)
        .header("x-aws-session-token", &creds.session_token)
        // Crate-owned body shape (issue #203) — a drifted field is a compile error.
        .json(&agentkeys_backend_client::MemoryPutBody {
            cap,
            plaintext_b64: STANDARD.encode(&plaintext),
            namespace: ns.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("worker put transport: {e}"))?;
    if !put_resp.status().is_success() {
        let status = put_resp.status();
        let body = put_resp.text().await.unwrap_or_default();
        return Err(format!("worker put {status}: {body}"));
    }
    let parsed: serde_json::Value = put_resp
        .json()
        .await
        .map_err(|e| format!("worker put parse: {e}"))?;
    Ok(parsed
        .get("s3_key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string())
}

/// Per-namespace memory-get (#201 Phase 4 lazy detail): cap-mint(`memory:<ns>`)
/// → worker `/v1/memory/get` → decrypt → parse the JSON array (tolerant of a
/// legacy single-body blob). The whole namespace decrypts in one round-trip.
/// `Ok(Some(entries))` when the namespace blob exists, `Ok(None)` when the
/// worker reports it MISSING (HTTP 404 / `NoSuchKey` — never written), and `Err`
/// on a real worker/transport/decrypt failure. The `Option` is what lets the
/// read-modify-write plant tell "new namespace" (write fresh) from "transient
/// error" (abort — never overwrite durable data) per codex finding 1.
async fn memory_get_ns_real(
    client: &reqwest::Client,
    ctx: &RealMemoryCtx,
    creds: &agentkeys_provisioner::AwsTempCreds,
    ns: &str,
) -> Result<Option<Vec<StoredMemoryEntry>>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "memory-get",
        &format!("memory:{ns}"),
    )
    .await?;
    let get_resp = client
        .post(format!("{}/v1/memory/get", ctx.memory_url))
        .header("x-aws-access-key-id", &creds.access_key_id)
        .header("x-aws-secret-access-key", &creds.secret_access_key)
        .header("x-aws-session-token", &creds.session_token)
        // Crate-owned body shape (issue #203).
        .json(&agentkeys_backend_client::MemoryGetBody {
            cap,
            namespace: ns.to_string(),
        })
        .send()
        .await
        .map_err(|e| format!("worker get transport: {e}"))?;
    if get_resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None); // namespace never written
    }
    if !get_resp.status().is_success() {
        let status = get_resp.status();
        let body = get_resp.text().await.unwrap_or_default();
        return Err(format!("worker get {status}: {body}"));
    }
    let parsed: serde_json::Value = get_resp
        .json()
        .await
        .map_err(|e| format!("worker get parse: {e}"))?;
    let b64 = parsed
        .get("plaintext_b64")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| format!("plaintext_b64 decode: {e}"))?;
    let plaintext = String::from_utf8(bytes).map_err(|e| format!("plaintext utf8: {e}"))?;
    Ok(Some(parse_stored_blob(&plaintext, ns)))
}

/// Config-store the master-only memory-types taxonomy (#201): cap-mint
/// (`config-store`, service `memory-taxonomy`) → config worker `/v1/config/put`.
/// Mints its own STS creds under the CONFIG role (distinct from the memory role
/// per arch.md §17.2 per-data-class bucket separation).
async fn config_store_taxonomy(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
    taxonomy: &MemoryTaxonomy,
) -> Result<(), String> {
    let plaintext = serde_json::to_vec(taxonomy).map_err(|e| format!("taxonomy serialize: {e}"))?;
    config_store_doc(client, ctx, TAXONOMY_SERVICE, &plaintext).await
}

/// Generic Config-class doc STORE (#201/#372 shape, service-parameterized):
/// master-self cap (`config-store`, `service`) → STS under the CONFIG role →
/// client-side v3 encrypt under the signer-derived per-(actor, service) KEK →
/// config worker `/v1/config/put`. Used by the taxonomy (`memory-taxonomy`)
/// and the #404 channel registry (`channel-registry`).
async fn config_store_doc(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
    service: &str,
    plaintext: &[u8],
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "config-store",
        service,
    )
    .await?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| format!("STS relay (config): {e}"))?;
    // #372 item 2: CLIENT-side encrypt under the signer-derived per-actor KEK
    // (v3 envelope). The worker stores the envelope verbatim — plaintext never
    // reaches it, and neither the storage plane nor any worker env can decrypt.
    let kek = derive_config_kek(ctx, service).await?;
    let aad = agentkeys_core::envelope_v3::aad_v3(&ctx.omni, service);
    let envelope = agentkeys_core::envelope_v3::encrypt_v3(&kek, plaintext, &aad)
        .map_err(|e| format!("config v3 encrypt: {e}"))?;
    let resp = client
        .post(format!("{}/v1/config/put", ctx.config_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        // Crate-owned body shape (issue #203) — config worker put body.
        .json(&agentkeys_backend_client::ConfigPutBody {
            cap,
            plaintext_b64: None,
            envelope_b64: Some(STANDARD.encode(&envelope)),
        })
        .send()
        .await
        .map_err(|e| format!("config put transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("config put {status}: {body}"));
    }
    Ok(())
}

/// Config-fetch the taxonomy (#201). `Ok(None)` ONLY when the object is
/// confirmed MISSING (HTTP 404 / `NoSuchKey` — never planted), so the list may
/// legitimately fall back to cache-derived categories. Any OTHER failure
/// (cap-mint, STS, config worker 5xx, decrypt/parse) is an `Err` that the caller
/// MUST surface — never silently downgrade to the cache, which would hide a
/// configured-but-broken Config behind a stale "looks empty" view (codex
/// finding 2).
async fn config_fetch_taxonomy(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
) -> Result<Option<MemoryTaxonomy>, String> {
    let Some(bytes) = config_fetch_doc(client, ctx, TAXONOMY_SERVICE).await? else {
        return Ok(None);
    };
    let taxonomy: MemoryTaxonomy =
        serde_json::from_slice(&bytes).map_err(|e| format!("taxonomy parse: {e}"))?;
    Ok(Some(taxonomy))
}

/// Generic Config-class doc FETCH (service-parameterized twin of
/// [`config_store_doc`]). `Ok(None)` ONLY on confirmed-missing (404); any other
/// failure is an `Err` the caller must surface (never silently downgrade).
async fn config_fetch_doc(
    client: &reqwest::Client,
    ctx: &RealConfigCtx,
    service: &str,
) -> Result<Option<Vec<u8>>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "config-fetch",
        service,
    )
    .await?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| format!("STS relay (config): {e}"))?;
    let resp = client
        .post(format!("{}/v1/config/get", ctx.config_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        // Crate-owned body shape (issue #203) — config worker get body.
        .json(&agentkeys_backend_client::ConfigGetBody { cap })
        .send()
        .await
        .map_err(|e| format!("config get transport: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Confirmed missing — nothing planted yet. The ONLY legitimate fallback.
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("config get {status}: {body}"));
    }
    // Crate-owned response shape (issue #203): exactly one of envelope_b64
    // (v3 — client-side decrypt under the signer-derived KEK, #372) /
    // plaintext_b64 (legacy v2 blob the worker decrypted) is set.
    let parsed: agentkeys_backend_client::ConfigGetResp = resp
        .json()
        .await
        .map_err(|e| format!("config get parse: {e}"))?;
    let bytes = match (parsed.envelope_b64, parsed.plaintext_b64) {
        (Some(env_b64), _) => {
            let envelope = STANDARD
                .decode(&env_b64)
                .map_err(|e| format!("{service} envelope decode: {e}"))?;
            let kek = derive_config_kek(ctx, service).await?;
            let aad = agentkeys_core::envelope_v3::aad_v3(&ctx.omni, service);
            agentkeys_core::envelope_v3::decrypt_v3(&kek, &envelope, &aad)
                .map_err(|e| format!("config v3 decrypt (signer-derived KEK): {e}"))?
        }
        (None, Some(pt_b64)) => STANDARD
            .decode(&pt_b64)
            .map_err(|e| format!("{service} plaintext decode: {e}"))?,
        (None, None) => {
            return Err("config get: response carried neither envelope_b64 nor \
                        plaintext_b64 — worker/client version mismatch"
                .into())
        }
    };
    Ok(Some(bytes))
}

// ── #404 channel registry — master-curated channel definitions ──────────────
//
// The registry is the master's id-anchored catalog of channels. The chain layer
// stays grant-anchored (free-form ids hashed into `channel-pub/sub:<id>`); the
// registry adds the operator-facing truths: WHICH ids exist, their display
// names, and therefore (a) the web app offers SELECTION at device pairing —
// never silent free-text creation — and (b) the daemon can re-derive channel
// names + device-ness from on-chain grant hashes after a restart (keccak of
// `channel-pub/sub:<id>` over every registry id).

/// Load the registry through the taxonomy-style cache: in-memory if present,
/// else config-fetch (`Ok(None)` = never created → empty), else — Config
/// UNCONFIGURED (dev / no-infra) — an empty cached-only registry.
async fn ensure_channel_registry(state: &UiBridgeState) -> Result<ChannelRegistry, String> {
    if let Some(r) = state.channel_registry.read().await.clone() {
        return Ok(r);
    }
    let loaded = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            match config_fetch_doc(&client, &ctx, CHANNEL_REGISTRY_SERVICE).await? {
                Some(bytes) => serde_json::from_slice::<ChannelRegistry>(&bytes)
                    .map_err(|e| format!("channel-registry parse: {e}"))?,
                None => ChannelRegistry::default(),
            }
        }
        None => ChannelRegistry::default(),
    };
    *state.channel_registry.write().await = Some(loaded.clone());
    Ok(loaded)
}

/// Persist + cache a mutated registry. Durable when Config is configured
/// (`"ok"`); dev/no-infra keeps cache-only (`"cached"`, taxonomy posture). A
/// configured-but-FAILING store returns `Err` WITHOUT touching the cache — the
/// mutation is rejected whole, never half-applied (no silent cache↔durable
/// divergence).
async fn persist_channel_registry(
    state: &UiBridgeState,
    next: ChannelRegistry,
) -> Result<&'static str, String> {
    let storage = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            let bytes =
                serde_json::to_vec(&next).map_err(|e| format!("registry serialize: {e}"))?;
            config_store_doc(&client, &ctx, CHANNEL_REGISTRY_SERVICE, &bytes).await?;
            "ok"
        }
        None => "cached",
    };
    *state.channel_registry.write().await = Some(next);
    Ok(storage)
}

// ── #424 binding manifest — durable readable pairing metadata ────────────────

/// Load the binding manifest through the taxonomy-style cache: in-memory if
/// present, else config-fetch (`Ok(None)` = never created → empty), else —
/// Config UNCONFIGURED (dev / no-infra) — an empty cached-only manifest.
async fn ensure_binding_manifest(state: &UiBridgeState) -> Result<BindingManifest, String> {
    if let Some(m) = state.binding_manifest.read().await.clone() {
        return Ok(m);
    }
    let loaded = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            match config_fetch_doc(&client, &ctx, BINDING_MANIFEST_SERVICE).await? {
                Some(bytes) => serde_json::from_slice::<BindingManifest>(&bytes)
                    .map_err(|e| format!("binding-manifest parse: {e}"))?,
                None => BindingManifest::default(),
            }
        }
        None => BindingManifest::default(),
    };
    *state.binding_manifest.write().await = Some(loaded.clone());
    Ok(loaded)
}

/// Persist + cache a mutated manifest (channel-registry posture: durable when
/// Config is configured, cache-only otherwise; a configured-but-FAILING store
/// returns `Err` without touching the cache).
async fn persist_binding_manifest(
    state: &UiBridgeState,
    next: BindingManifest,
) -> Result<&'static str, String> {
    let storage = match real_config_ctx(state).await? {
        Some(ctx) => {
            let client = reqwest::Client::new();
            let bytes =
                serde_json::to_vec(&next).map_err(|e| format!("manifest serialize: {e}"))?;
            config_store_doc(&client, &ctx, BINDING_MANIFEST_SERVICE, &bytes).await?;
            "ok"
        }
        None => "cached",
    };
    *state.binding_manifest.write().await = Some(next);
    Ok(storage)
}

/// Upsert one bound actor's entry (accept / scope commit). Best-effort from the
/// caller's perspective — the on-chain bind already landed, so a store failure
/// must WARN loudly (the actor's kind + names would not survive a restart) but
/// never fail the ceremony that triggered it.
async fn upsert_binding_manifest_entry(state: &UiBridgeState, entry: BindingManifestEntry) {
    let label = entry.label.clone();
    let mut manifest = match ensure_binding_manifest(state).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                target: "agentkeys.daemon.ui_bridge",
                label = %label,
                "binding manifest LOAD failed — {e}; this actor's kind + service names \
                 will NOT survive a daemon restart until the next successful upsert"
            );
            return;
        }
    };
    manifest.upsert(entry);
    match persist_binding_manifest(state, manifest).await {
        Ok(storage) => tracing::info!(
            target: "agentkeys.daemon.ui_bridge",
            label = %label,
            storage,
            "binding manifest upserted"
        ),
        Err(e) => tracing::warn!(
            target: "agentkeys.daemon.ui_bridge",
            label = %label,
            "binding manifest STORE failed — {e}; this actor's kind + service names \
             will NOT survive a daemon restart until the next successful upsert"
        ),
    }
}

/// `keccak(channel-pub:<id>)` / `keccak(channel-sub:<id>)` (`0x`-hex, the
/// on-chain service-id spelling) → the service NAME, for every registry id.
/// The reverse map that re-names an actor's opaque scope hashes.
fn channel_service_candidates(registry: &ChannelRegistry) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for ch in &registry.channels {
        for dir in ["channel-pub", "channel-sub"] {
            let name = format!("{dir}:{}", ch.id.to_lowercase());
            let h = format!(
                "0x{}",
                hex::encode(agentkeys_core::device_crypto::keccak256(name.as_bytes()))
            );
            map.insert(h, name);
        }
    }
    map
}

/// Which actors hold a grant on channel `id` — by NAME (in `services`) or by
/// on-chain HASH (in `scope_unknown_service_ids`). Pure for testability; the
/// delete handler refuses while this is non-empty (revoke the grants first —
/// deleting a definition under live grants would orphan them back to hashes).
fn channel_holders(actors: &HashMap<String, ApiActor>, id: &str) -> Vec<String> {
    let idl = id.to_lowercase();
    let names = [format!("channel-pub:{idl}"), format!("channel-sub:{idl}")];
    let hashes: Vec<String> = names
        .iter()
        .map(|n| {
            format!(
                "0x{}",
                hex::encode(agentkeys_core::device_crypto::keccak256(n.as_bytes()))
            )
        })
        .collect();
    let mut holders: Vec<String> = actors
        .values()
        .filter(|a| {
            a.services
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|s| names.contains(&s.to_lowercase()))
                || a.scope_unknown_service_ids
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .any(|h| hashes.contains(&h.to_lowercase()))
        })
        .map(|a| a.label.clone())
        .collect();
    holders.sort();
    holders.dedup();
    holders
}

fn registry_err(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// The `storage` flag every registry response carries: `"ok"` = durable
/// Config-class doc; `"cached"` = Config unconfigured (dev-only, in-memory).
fn registry_storage_label(state: &UiBridgeState) -> &'static str {
    if state.config_url.is_some() {
        "ok"
    } else {
        "cached"
    }
}

async fn require_master_session(state: &UiBridgeState) -> Result<(), axum::response::Response> {
    match state.onboarding_session.read().await.as_ref() {
        Some(s) if !s.j1.is_empty() => Ok(()),
        _ => Err(registry_err(
            StatusCode::FORBIDDEN,
            "no master session — sign in first",
        )),
    }
}

/// GET /v1/channels — the registry, master-session-gated.
async fn list_channels(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    if let Err(r) = require_master_session(&state).await {
        return r;
    }
    match ensure_channel_registry(&state).await {
        Ok(reg) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "channels": reg.channels,
                "storage": registry_storage_label(&state),
            })),
        )
            .into_response(),
        Err(e) => registry_err(StatusCode::BAD_GATEWAY, &format!("channel registry: {e}")),
    }
}

#[derive(Debug, Deserialize)]
struct CreateChannelRequest {
    id: String,
    name: String,
    #[serde(default)]
    note: Option<String>,
}

/// POST /v1/channels — create a channel definition. The id is validated +
/// IMMUTABLE from here on (it is the on-chain anchor); duplicates 409.
async fn create_channel(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<CreateChannelRequest>,
) -> axum::response::Response {
    if let Err(r) = require_master_session(&state).await {
        return r;
    }
    let id = req.id.trim().to_lowercase();
    if !valid_channel_id(&id) {
        return registry_err(
            StatusCode::BAD_REQUEST,
            "channel id must be 1-48 chars of [a-z0-9-], not starting/ending with '-' — it is the immutable on-chain anchor",
        );
    }
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return registry_err(StatusCode::BAD_REQUEST, "channel name must not be empty");
    }
    let mut reg = match ensure_channel_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("channel registry: {e}")),
    };
    if reg.channels.iter().any(|c| c.id == id) {
        return registry_err(
            StatusCode::CONFLICT,
            "a channel with this id already exists (ids are immutable anchors — pick another)",
        );
    }
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let channel = ApiChannel {
        id,
        name,
        note: req
            .note
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty()),
        created_at,
    };
    reg.channels.push(channel.clone());
    match persist_channel_registry(&state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(serde_json::json!({ "channel": channel, "storage": storage })),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!("channel registry store failed — nothing created: {e}"),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct UpdateChannelRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// POST /v1/channels/:id — edit DISPLAY fields (name/note). The id is the
/// immutable anchor: there is deliberately no rename — even when the display
/// name changes, the id stays what the on-chain grants hash.
async fn update_channel(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateChannelRequest>,
) -> axum::response::Response {
    if let Err(r) = require_master_session(&state).await {
        return r;
    }
    let mut reg = match ensure_channel_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("channel registry: {e}")),
    };
    let idl = id.to_lowercase();
    let Some(ch) = reg.channels.iter_mut().find(|c| c.id == idl) else {
        return registry_err(StatusCode::NOT_FOUND, "no channel with that id");
    };
    if let Some(name) = req.name {
        let name = name.trim().to_string();
        if name.is_empty() {
            return registry_err(StatusCode::BAD_REQUEST, "channel name must not be empty");
        }
        ch.name = name;
    }
    if let Some(note) = req.note {
        let note = note.trim().to_string();
        ch.note = (!note.is_empty()).then_some(note);
    }
    let updated = reg.channels.iter().find(|c| c.id == idl).cloned();
    match persist_channel_registry(&state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(serde_json::json!({ "channel": updated, "storage": storage })),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!("channel registry store failed — nothing changed: {e}"),
        ),
    }
}

/// POST /v1/channels/:id/delete — remove a definition. REFUSED while any actor
/// still holds a grant on the id (by name or on-chain hash): revoke those first
/// (device page / actor page), else the live grants would orphan back to
/// unreadable hashes. Mirrors the "no silent divergence" posture.
async fn delete_channel(
    State(state): State<SharedUiBridgeState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = require_master_session(&state).await {
        return r;
    }
    let mut reg = match ensure_channel_registry(&state).await {
        Ok(r) => r,
        Err(e) => return registry_err(StatusCode::BAD_GATEWAY, &format!("channel registry: {e}")),
    };
    let idl = id.to_lowercase();
    if !reg.channels.iter().any(|c| c.id == idl) {
        return registry_err(StatusCode::NOT_FOUND, "no channel with that id");
    }
    let holders = channel_holders(&*state.actors.read().await, &idl);
    if !holders.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "channel is in use — revoke its grants first",
                "holders": holders,
            })),
        )
            .into_response();
    }
    reg.channels.retain(|c| c.id != idl);
    match persist_channel_registry(&state, reg).await {
        Ok(storage) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "storage": storage })),
        )
            .into_response(),
        Err(e) => registry_err(
            StatusCode::BAD_GATEWAY,
            &format!("channel registry store failed — nothing deleted: {e}"),
        ),
    }
}

/// Read-modify-write the durable taxonomy: config-fetch the current
/// `config/memory-taxonomy.enc`, MERGE `new_categories` in (preserving every
/// existing entry, [`merge_categories`]), and config-store the union. Returns the
/// merged categories now durable.
///
/// A fetch ERROR aborts WITHOUT storing — never overwrite a taxonomy we failed to
/// read (the #201 finding-1 footgun, now guarding the category index too). A
/// confirmed-missing object (`Ok(None)`) is a fresh start, not an error. Shared by
/// the test-only `plant` (cache-derived categories) and the authored `init`
/// (preset categories, #207 item 1A) so both compose without clobbering.
async fn reconcile_taxonomy(
    client: &reqwest::Client,
    cfg: &RealConfigCtx,
    new_categories: &[MemoryCategory],
) -> Result<Vec<MemoryCategory>, String> {
    let existing = match config_fetch_taxonomy(client, cfg).await {
        Ok(Some(tax)) => tax.categories,
        Ok(None) => Vec::new(),
        Err(e) => return Err(e),
    };
    let merged = merge_categories(existing, new_categories);
    let taxonomy = MemoryTaxonomy {
        version: 1,
        categories: merged.clone(),
    };
    config_store_taxonomy(client, cfg, &taxonomy).await?;
    Ok(merged)
}

/// Idempotent plant: each entry's content_hash is the dedup key. Re-planting
/// the same content is a no-op (skipped++), so "prevent duplicate plant" is
/// enforced server-side, not just in the UI. Returns planted/skipped counts +
/// the resulting total. An audit row records the plant.
// ── #339 P2 — absorption-inbox curate (the master-hub "push" landing) ─────────

#[derive(Debug, serde::Deserialize)]
struct InboxCurateRequest {
    s3_key: String,
    /// #390 §16.2 — the viewed-body watermark for `skill` proposals: the item's
    /// `content_hash` as returned by `/v1/master/inbox/entry`. A skill accept
    /// WITHOUT a matching hash is rejected (the gate can't prove the master saw
    /// the body). Ignored for `knowledge`; `persona` is never adoptable.
    #[serde(default)]
    confirm_content_hash: Option<String>,
}

/// #390 §16.2 — the per-kind skill size cap enforced at the curate gate
/// (near-executable content ⇒ higher injection/behavior risk than knowledge).
const SKILL_MAX_BYTES: usize = 64 * 1024;

/// Mint a master-self inbox cap (Fetch op, `service = "inbox"`,
/// `operator == actor == O_master` so the broker skips the on-chain scope check)
/// and POST it to a worker inbox endpoint, reusing the master's memory-role STS
/// creds. `extra` is merged into the request body alongside `cap`.
async fn inbox_worker_post(
    http: &reqwest::Client,
    ctx: &RealMemoryCtx,
    creds: &agentkeys_provisioner::AwsTempCreds,
    path: &str,
    extra: serde_json::Value,
) -> Result<serde_json::Value, (axum::http::StatusCode, String)> {
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "memory-get",
        "inbox",
    )
    .await
    .map_err(|e| (axum::http::StatusCode::BAD_GATEWAY, e))?;
    let mut body = serde_json::json!({ "cap": cap });
    if let (Some(obj), Some(extra_obj)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let resp = http
        .post(format!("{}{}", ctx.memory_url, path))
        .header("x-aws-access-key-id", &creds.access_key_id)
        .header("x-aws-secret-access-key", &creds.secret_access_key)
        .header("x-aws-session-token", &creds.session_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("inbox worker {path} transport: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err((
            axum::http::StatusCode::BAD_GATEWAY,
            format!("inbox worker {path} {status}: {text}"),
        ));
    }
    resp.json().await.map_err(|e| {
        (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("inbox worker {path} parse: {e}"),
        )
    })
}

/// `GET /v1/master/inbox` — the curate queue: list every delegate proposal in
/// the master's absorption inbox (master-self).
async fn list_master_inbox(State(state): State<SharedUiBridgeState>) -> axum::response::Response {
    let ctx = match real_memory_ctx(&state).await {
        Ok(Some(ctx)) => ctx,
        // No real chain configured → empty queue (in-memory fallback has no inbox).
        Ok(None) => {
            let empty: Vec<ApiInboxItem> = Vec::new();
            return (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ "items": empty })),
            )
                .into_response();
        }
        Err(reason) => {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": reason })),
            )
                .into_response()
        }
    };
    let http = reqwest::Client::new();
    let creds = match agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("STS relay: {e}") })),
            )
                .into_response()
        }
    };
    match inbox_worker_post(
        &http,
        &ctx,
        &creds,
        "/v1/memory/inbox-list",
        serde_json::json!({}),
    )
    .await
    {
        Ok(v) => {
            let items: Vec<ApiInboxItem> = v
                .get("items")
                .and_then(|i| serde_json::from_value(i.clone()).ok())
                .unwrap_or_default();
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ "items": items })),
            )
                .into_response()
        }
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// `POST /v1/master/inbox/entry` — read ONE proposal's full body so the master can
/// review what was pushed before accept/reject (master-self). The worker already
/// holds the body via `/v1/memory/inbox-get`; this decodes it to plaintext.
async fn get_master_inbox_entry(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<InboxCurateRequest>,
) -> axum::response::Response {
    let ctx = match real_memory_ctx(&state).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "inbox requires a configured chain + master session" })),
            )
                .into_response()
        }
        Err(reason) => {
            return (axum::http::StatusCode::CONFLICT, Json(serde_json::json!({ "error": reason })))
                .into_response()
        }
    };
    let http = reqwest::Client::new();
    let creds = match agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("STS relay: {e}") })),
            )
                .into_response()
        }
    };
    match inbox_worker_post(
        &http,
        &ctx,
        &creds,
        "/v1/memory/inbox-get",
        serde_json::json!({ "s3_key": req.s3_key }),
    )
    .await
    {
        Ok(v) => {
            let item = v.get("item").cloned().unwrap_or(serde_json::Value::Null);
            let body_b64 = item
                .get("body_b64")
                .and_then(|x| x.as_str())
                .unwrap_or_default();
            let body = {
                use base64::{engine::general_purpose::STANDARD, Engine};
                match STANDARD.decode(body_b64) {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    Err(e) => return (
                        axum::http::StatusCode::BAD_GATEWAY,
                        Json(
                            serde_json::json!({ "error": format!("inbox item body decode: {e}") }),
                        ),
                    )
                        .into_response(),
                }
            };
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "body": body,
                    "ns": item.get("ns"),
                    "key": item.get("key"),
                    "source_delegate_omni": item.get("source_delegate_omni"),
                    "content_hash": item.get("content_hash"),
                    "ts": item.get("ts"),
                    // #390 — absent on pre-#390 envelopes ⇒ knowledge.
                    "kind": item.get("kind").cloned()
                        .unwrap_or_else(|| serde_json::json!("knowledge")),
                })),
            )
                .into_response()
        }
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// #390 §16.2 — the per-kind adoption gate applied by `accept_master_inbox`
/// BEFORE the plant. Pure so the policy is unit-testable: `knowledge` passes
/// unchanged; `skill` requires the viewed-body watermark (`confirm_content_hash`
/// == the item's worker-stamped hash — proof the body was reviewed) and the
/// [`SKILL_MAX_BYTES`] cap; `persona` is NEVER inbox-adoptable (master-authored
/// only — edited in parent-control, its gate is simply closed to delegates).
fn curate_gate(
    kind: ContextKind,
    body_bytes: usize,
    confirm_content_hash: Option<&str>,
    item_content_hash: &str,
) -> Result<(), (axum::http::StatusCode, String)> {
    match kind {
        ContextKind::Knowledge => Ok(()),
        ContextKind::Persona => Err((
            axum::http::StatusCode::FORBIDDEN,
            "persona_not_inbox_adoptable: persona is master-authored only — reject this \
             proposal and edit the delegate's persona in parent-control (#390)"
                .to_string(),
        )),
        ContextKind::Skill => {
            if body_bytes > SKILL_MAX_BYTES {
                return Err((
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "skill_too_large: {body_bytes} bytes exceeds the {SKILL_MAX_BYTES}-byte \
                         skill cap"
                    ),
                ));
            }
            match confirm_content_hash {
                Some(h) if h == item_content_hash => Ok(()),
                Some(_) => Err((
                    axum::http::StatusCode::CONFLICT,
                    "skill_review_stale: confirm_content_hash does not match the proposal — \
                     re-view the body and retry with the hash it prints"
                        .to_string(),
                )),
                None => Err((
                    axum::http::StatusCode::PRECONDITION_REQUIRED,
                    "skill_review_required: a skill accept must carry confirm_content_hash \
                     (view the body first; the hash proves it was reviewed)"
                        .to_string(),
                )),
            }
        }
    }
}

/// `POST /v1/master/inbox/accept` — curate one proposal INTO canonical memory
/// (the master's PR-merge), then GC the inbox object. Reuses the existing master
/// memory plant (read-modify-write merge + taxonomy reconcile). #390: gated
/// per-kind by [`curate_gate`] first.
async fn accept_master_inbox(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<InboxCurateRequest>,
) -> axum::response::Response {
    let ctx = match real_memory_ctx(&state).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "inbox curate requires a configured chain + master session" })),
            )
                .into_response()
        }
        Err(reason) => {
            return (axum::http::StatusCode::CONFLICT, Json(serde_json::json!({ "error": reason })))
                .into_response()
        }
    };
    let http = reqwest::Client::new();
    let creds = match agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("STS relay: {e}") })),
            )
                .into_response()
        }
    };

    // 1. Read the proposal (worker-stamped provenance + the proposed body).
    let item = match inbox_worker_post(
        &http,
        &ctx,
        &creds,
        "/v1/memory/inbox-get",
        serde_json::json!({ "s3_key": req.s3_key }),
    )
    .await
    {
        Ok(v) => v.get("item").cloned().unwrap_or(serde_json::Value::Null),
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let ns = item
        .get("ns")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let key = item
        .get("key")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let body_b64 = item
        .get("body_b64")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let body = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        match STANDARD.decode(body_b64) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(e) => {
                return (
                    axum::http::StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({ "error": format!("inbox item body decode: {e}") })),
                )
                    .into_response()
            }
        }
    };
    if ns.is_empty() || key.is_empty() {
        return (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "inbox item missing ns/key" })),
        )
            .into_response();
    }

    // 1b. #390 §16.2 — the PER-KIND adoption gate (direction is a gate-policy
    // outcome, not a class property): knowledge = today's accept; skill =
    // viewed-body watermark + size cap; persona = never inbox-adoptable.
    let kind: ContextKind = item
        .get("kind")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let item_hash = item
        .get("content_hash")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if let Err((status, reason)) = curate_gate(
        kind,
        body.len(),
        req.confirm_content_hash.as_deref(),
        item_hash,
    ) {
        return (status, Json(serde_json::json!({ "error": reason }))).into_response();
    }

    // 2. Curate INTO canonical via the existing plant (merge + taxonomy).
    let preview: String = body.chars().take(120).collect();
    let entry = ApiMemoryEntry {
        ns: ns.clone(),
        key: key.clone(),
        title: key.clone(),
        bytes: body.len() as u64,
        version: "1".to_string(),
        updated: String::new(),
        preview,
        body,
        content_hash: String::new(),
        kind,
    };
    let plant = match plant_master_memory_inner(
        &state,
        MasterMemoryPlantRequest {
            entries: vec![entry],
        },
    )
    .await
    {
        Ok(resp) => resp,
        Err((status, reason)) => {
            return (
                status,
                Json(serde_json::json!({ "error": format!("curate plant failed: {reason}") })),
            )
                .into_response()
        }
    };

    // 3. GC the inbox object (delete-on-accept).
    if let Err((status, reason)) = inbox_worker_post(
        &http,
        &ctx,
        &creds,
        "/v1/memory/inbox-delete",
        serde_json::json!({ "s3_key": req.s3_key }),
    )
    .await
    {
        // The merge committed; surface the GC failure but don't claim a clean accept.
        return (
            status,
            Json(serde_json::json!({
                "ok": false,
                "planted": plant.planted,
                "ns": ns,
                "key": key,
                "error": format!("curated into canonical but inbox GC failed: {reason}"),
            })),
        )
            .into_response();
    }

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "planted": plant.planted, "ns": ns, "key": key })),
    )
        .into_response()
}

/// `POST /v1/master/inbox/reject` — discard one proposal (GC the inbox object,
/// never enters canonical).
async fn reject_master_inbox(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<InboxCurateRequest>,
) -> axum::response::Response {
    let ctx = match real_memory_ctx(&state).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "inbox curate requires a configured chain + master session" })),
            )
                .into_response()
        }
        Err(reason) => {
            return (axum::http::StatusCode::CONFLICT, Json(serde_json::json!({ "error": reason })))
                .into_response()
        }
    };
    let http = reqwest::Client::new();
    let creds = match agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("STS relay: {e}") })),
            )
                .into_response()
        }
    };
    match inbox_worker_post(
        &http,
        &ctx,
        &creds,
        "/v1/memory/inbox-delete",
        serde_json::json!({ "s3_key": req.s3_key }),
    )
    .await
    {
        Ok(_) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "deleted": true })),
        )
            .into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

// ── #390 — persona editor + sandbox apply/restart (master-hub §16) ──────────
//
// Persona (`SOUL.md`) is the strictest context kind: master-authored only,
// validated at EDIT time (crate::persona), stored VERSIONED in the reserved
// `persona` memory namespace (key `soul:<omni>` + `soul:<omni>@<n>` history),
// and APPLIED into the bound agent's sandbox via the bridge's
// `/v1/context/apply` (file write + ACP re-source — hermes reloads SOUL.md at
// session creation). Storage rides the SAME per-ns machinery as the plant
// (real worker or in-memory fallback) but writes the array WHOLESALE under the
// plant lock — rotation is not a merge.

/// The daemon-facing persona state for one delegate (the editor's GET).
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiPersonaState {
    pub delegate_omni: String,
    /// The live persona document (`soul:<omni>`), if one was ever authored.
    pub current: Option<ApiMemoryEntry>,
    /// Superseded versions, newest first (rollback targets, max 5 kept).
    pub versions: Vec<ApiMemoryEntry>,
    /// Whether a sandbox bridge is configured (edits apply live vs store-only).
    pub sandbox_configured: bool,
}

/// Outcome of a persona edit/rollback. `applied` is the sandbox leg — `false`
/// with a reason in `apply_detail` when the sandbox is unconfigured/unreachable
/// (the canonical store SUCCEEDED either way; never a silent partial success).
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiPersonaEditResponse {
    pub ok: bool,
    pub version: u32,
    pub applied: bool,
    pub apply_detail: String,
}

#[derive(Debug, Deserialize)]
struct PersonaQuery {
    delegate: String,
}

#[derive(Debug, Deserialize)]
struct PersonaEditRequest {
    delegate_omni: String,
    body: String,
}

#[derive(Debug, Deserialize)]
struct PersonaRollbackRequest {
    delegate_omni: String,
    version: u32,
}

/// A delegate omni for persona keying: `0x` + ≥8 hex chars (an actor omni is
/// 20 bytes, but the dev/harness fixtures use shorter ids — the key derivation
/// only needs a stable, hex-shaped identifier), lowercased by
/// [`persona_soul_key`].
fn validate_delegate_omni(omni: &str) -> Result<(), String> {
    let hex = omni
        .strip_prefix("0x")
        .or_else(|| omni.strip_prefix("0X"))
        .unwrap_or(omni);
    if hex.len() >= 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "delegate_omni must be a 0x-hex actor omni (≥8 hex chars), got `{omni}`"
        ))
    }
}

/// UTC calendar date (`YYYY-MM-DD`) for persona `updated` stamps — civil-date
/// math from unix days (no chrono dep; Hinnant's algorithm).
fn now_date_utc() -> String {
    let days = (now_unix() / 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The persona storage backend: the real per-ns worker chain when configured,
/// else the in-memory cache (dev / headless CI — same split as the plant).
enum PersonaBackend {
    Real(Box<RealMemoryCtx>, agentkeys_provisioner::AwsTempCreds),
    Cache,
}

async fn persona_backend(
    state: &SharedUiBridgeState,
) -> Result<PersonaBackend, (axum::http::StatusCode, String)> {
    match real_memory_ctx(state).await {
        Ok(Some(ctx)) => {
            let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
                &ctx.broker,
                &ctx.j1,
                &ctx.role_arn,
                &ctx.region,
            )
            .await
            .map_err(|e| {
                (
                    axum::http::StatusCode::BAD_GATEWAY,
                    format!("STS relay: {e}"),
                )
            })?;
            Ok(PersonaBackend::Real(Box::new(ctx), creds))
        }
        Ok(None) => Ok(PersonaBackend::Cache),
        Err(reason) => Err((axum::http::StatusCode::CONFLICT, reason)),
    }
}

/// Load the WHOLE persona namespace array (all delegates). Empty when never
/// written.
async fn persona_load(
    state: &SharedUiBridgeState,
    backend: &PersonaBackend,
) -> Result<Vec<StoredMemoryEntry>, (axum::http::StatusCode, String)> {
    match backend {
        PersonaBackend::Real(ctx, creds) => {
            let client = reqwest::Client::new();
            memory_get_ns_real(&client, ctx, creds, PERSONA_NAMESPACE)
                .await
                .map(|opt| opt.unwrap_or_default())
                .map_err(|e| {
                    (
                        axum::http::StatusCode::BAD_GATEWAY,
                        format!("persona read of memory:{PERSONA_NAMESPACE} failed: {e}"),
                    )
                })
        }
        PersonaBackend::Cache => {
            let cache = state.master_memory.read().await;
            Ok(cache
                .values()
                .filter(|e| e.ns == PERSONA_NAMESPACE)
                .map(|e| e.to_stored())
                .collect())
        }
    }
}

/// Write the WHOLE persona namespace array back (rotation output). The caller
/// holds the plant lock, so this read-modify-write can't race a concurrent
/// plant/edit.
async fn persona_store(
    state: &SharedUiBridgeState,
    backend: &PersonaBackend,
    entries: &[StoredMemoryEntry],
) -> Result<(), (axum::http::StatusCode, String)> {
    match backend {
        PersonaBackend::Real(ctx, creds) => {
            let client = reqwest::Client::new();
            memory_put_ns_real(&client, ctx, creds, PERSONA_NAMESPACE, entries)
                .await
                .map(|_| ())
                .map_err(|e| {
                    (
                        axum::http::StatusCode::BAD_GATEWAY,
                        format!("persona write of memory:{PERSONA_NAMESPACE} failed: {e}"),
                    )
                })
        }
        PersonaBackend::Cache => {
            let mut cache = state.master_memory.write().await;
            cache.retain(|_, e| e.ns != PERSONA_NAMESPACE);
            for s in entries {
                let mut api = ApiMemoryEntry::from_stored(PERSONA_NAMESPACE, s.clone());
                api.content_hash = api.compute_hash();
                cache.insert(api.content_hash.clone(), api);
            }
            Ok(())
        }
    }
}

/// One request to the configured sandbox bridge (hermes_bridge.py). `Err` is a
/// human-readable transport/HTTP reason — the callers surface it explicitly.
async fn sandbox_bridge_request(
    state: &SharedUiBridgeState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    sandbox_bridge_request_instanced(state, method, path, body, None).await
}

/// #428/#430 per-delegate variant: when `instance` is set, the request carries
/// the veFaaS session-affinity header `x-faas-instance-name: <SandboxId>` so
/// the shared gateway routes it to THAT delegate's sandbox. `None` keeps the
/// single-bridge behavior (local dev / one-sandbox hosts, where a direct
/// bridge ignores the header harmlessly).
async fn sandbox_bridge_request_instanced(
    state: &SharedUiBridgeState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
    instance: Option<&str>,
) -> Result<serde_json::Value, String> {
    let base = state.sandbox_bridge_url.as_deref().ok_or_else(|| {
        "sandbox_unconfigured: no --sandbox-bridge-url / AGENTKEYS_SANDBOX_BRIDGE_URL".to_string()
    })?;
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("bridge client: {e}"))?;
    let mut req = client.request(method, &url);
    if let Some(token) = state.sandbox_bridge_token.as_deref() {
        req = req.bearer_auth(token);
    }
    if let Some(id) = instance.filter(|i| !i.is_empty()) {
        req = req.header("x-faas-instance-name", id);
    }
    if let Some(b) = body {
        req = req.json(&b);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("bridge {url} transport: {e}"))?;
    let status = resp.status();
    let value: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("bridge {url} parse: {e}"))?;
    if !status.is_success() {
        let err = value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("(no error body)");
        return Err(format!("bridge {url} {status}: {err}"));
    }
    Ok(value)
}

/// Apply a persona body into the sandbox (file write + ACP re-source, the #390
/// distribution leg). Returns `(applied, detail)` — an unconfigured/unreachable
/// sandbox is NOT an edit failure (the canonical store already committed), but
/// it is always surfaced, never silently swallowed.
async fn apply_persona_to_sandbox(
    state: &SharedUiBridgeState,
    soul_body: &str,
    instance: Option<&str>,
) -> (bool, String) {
    if state.sandbox_bridge_url.is_none() {
        return (
            false,
            "sandbox_unconfigured: stored canonically; the sandbox picks it up at next spawn"
                .to_string(),
        );
    }
    use base64::{engine::general_purpose::STANDARD, Engine};
    let body = serde_json::json!({
        "files": { "soul": STANDARD.encode(soul_body.as_bytes()) },
        "restart": true,
    });
    match sandbox_bridge_request_instanced(
        state,
        reqwest::Method::POST,
        "/v1/context/apply",
        Some(body),
        instance,
    )
    .await
    {
        Ok(v) => {
            let restarted = v
                .get("restarted")
                .and_then(|r| r.as_bool())
                .unwrap_or(false);
            (
                true,
                if restarted {
                    "applied to the sandbox; agent re-sourced (fresh ACP session)".to_string()
                } else {
                    "applied to the sandbox (no restart — takes effect at next re-source)"
                        .to_string()
                },
            )
        }
        Err(e) => (
            false,
            format!("stored canonically but sandbox apply failed: {e}"),
        ),
    }
}

/// `GET /v1/master/persona?delegate=0x…` — the editor state: current + history.
async fn get_master_persona(
    State(state): State<SharedUiBridgeState>,
    axum::extract::Query(q): axum::extract::Query<PersonaQuery>,
) -> axum::response::Response {
    if let Err(e) = validate_delegate_omni(&q.delegate) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    let backend = match persona_backend(&state).await {
        Ok(b) => b,
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let entries = match persona_load(&state, &backend).await {
        Ok(e) => e,
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let soul_key = persona_soul_key(&q.delegate);
    let (current, versions) = crate::persona::persona_view(entries, &soul_key);
    let view = ApiPersonaState {
        delegate_omni: normalize_omni_0x(&q.delegate).to_lowercase(),
        current: current.map(|s| ApiMemoryEntry::from_stored(PERSONA_NAMESPACE, s)),
        versions: versions
            .into_iter()
            .map(|s| ApiMemoryEntry::from_stored(PERSONA_NAMESPACE, s))
            .collect(),
        sandbox_configured: state.sandbox_bridge_url.is_some(),
    };
    (axum::http::StatusCode::OK, Json(view)).into_response()
}

/// Shared store path for edit + rollback: rotate under the plant lock, write,
/// apply to the sandbox, emit the audit event. `new_body` was ALREADY validated.
async fn persona_commit(
    state: &SharedUiBridgeState,
    delegate_omni: &str,
    new_body: &str,
    audit_kind: &str,
    audit_detail: String,
    instance: Option<&str>,
) -> Result<ApiPersonaEditResponse, (axum::http::StatusCode, String)> {
    let backend = persona_backend(state).await?;
    let soul_key = persona_soul_key(delegate_omni);
    let version;
    {
        // Rotation is a read-modify-write of the whole namespace array — hold
        // the plant lock so a concurrent plant/edit can't interleave.
        let _guard = state.plant_lock.lock().await;
        let entries = persona_load(state, &backend).await?;
        let (rotated, v) =
            crate::persona::rotate_persona(entries, &soul_key, new_body, &now_date_utc());
        persona_store(state, &backend, &rotated).await?;
        version = v;
    }
    let (applied, apply_detail) = apply_persona_to_sandbox(state, new_body, instance).await;
    let evt = ApiAuditEvent {
        id: format!("e-persona-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: audit_kind.into(),
        detail: format!("{audit_detail} · v{version} · applied: {applied}"),
        chip: "persona".into(),
        sev: "ok".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(state, evt).await;
    Ok(ApiPersonaEditResponse {
        ok: true,
        version,
        applied,
        apply_detail,
    })
}

/// `POST /v1/master/persona` — author/replace one delegate's persona document
/// (#390 acceptance 2). Edit-time validation (guardrail, secrets, size) happens
/// HERE — nothing invalid enters canonical; the apply leg never re-validates.
async fn edit_master_persona(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<PersonaEditRequest>,
) -> axum::response::Response {
    if let Err(e) = validate_delegate_omni(&req.delegate_omni) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    if let Err(e) = crate::persona::validate_persona_body(&req.body) {
        return (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    match persona_commit(
        &state,
        &req.delegate_omni,
        &req.body,
        "persona.edit",
        format!(
            "persona edited for delegate {}",
            normalize_omni_0x(&req.delegate_omni).to_lowercase()
        ),
        None,
    )
    .await
    {
        Ok(resp) => (axum::http::StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// `POST /v1/master/persona/rollback` — promote a kept history version back to
/// current (§16.2 item 5). The rollback is itself a new version (v<max+1>), so
/// history stays linear and auditable.
async fn rollback_master_persona(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<PersonaRollbackRequest>,
) -> axum::response::Response {
    if let Err(e) = validate_delegate_omni(&req.delegate_omni) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    let backend = match persona_backend(&state).await {
        Ok(b) => b,
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let entries = match persona_load(&state, &backend).await {
        Ok(e) => e,
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let soul_key = persona_soul_key(&req.delegate_omni);
    let Some(body) = crate::persona::persona_body_for_version(&entries, &soul_key, req.version)
    else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!(
                    "persona_version_not_found: v{} is not in the kept history (max {} versions)",
                    req.version,
                    crate::persona::PERSONA_HISTORY_KEEP
                )
            })),
        )
            .into_response();
    };
    match persona_commit(
        &state,
        &req.delegate_omni,
        &body,
        "persona.rollback",
        format!(
            "persona rolled back to v{} for delegate {}",
            req.version,
            normalize_omni_0x(&req.delegate_omni).to_lowercase()
        ),
        None,
    )
    .await
    {
        Ok(resp) => (axum::http::StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// `POST /v1/master/persona/delete` — remove one delegate's persona document
/// AND its kept history (e.g. after unbinding the delegate, or demo cleanup).
/// Other delegates' entries in the shared `persona` namespace are untouched.
async fn delete_master_persona(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<PersonaQueryBody>,
) -> axum::response::Response {
    if let Err(e) = validate_delegate_omni(&req.delegate_omni) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response();
    }
    let backend = match persona_backend(&state).await {
        Ok(b) => b,
        Err((status, reason)) => {
            return (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    };
    let soul_key = persona_soul_key(&req.delegate_omni);
    let prefix = format!("{soul_key}@");
    let removed;
    {
        let _guard = state.plant_lock.lock().await;
        let entries = match persona_load(&state, &backend).await {
            Ok(e) => e,
            Err((status, reason)) => {
                return (status, Json(serde_json::json!({ "error": reason }))).into_response()
            }
        };
        let before = entries.len();
        let kept: Vec<StoredMemoryEntry> = entries
            .into_iter()
            .filter(|e| e.key != soul_key && !e.key.starts_with(&prefix))
            .collect();
        removed = before - kept.len();
        if removed > 0 {
            if let Err((status, reason)) = persona_store(&state, &backend, &kept).await {
                return (status, Json(serde_json::json!({ "error": reason }))).into_response();
            }
        }
    }
    if removed > 0 {
        let evt = ApiAuditEvent {
            id: format!("e-persona-del-{}", now_unix()),
            ts: now_ts_hms(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "persona.delete".into(),
            detail: format!(
                "persona removed ({removed} version(s)) for delegate {}",
                normalize_omni_0x(&req.delegate_omni).to_lowercase()
            ),
            chip: "persona".into(),
            sev: "ok".into(),
            tx_hash: None,
            audit_envelope_hashes: None,
        };
        push_audit(&state, evt).await;
    }
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "removed": removed })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct PersonaQueryBody {
    delegate_omni: String,
}

/// `POST /v1/master/agent/restart` — the explicit re-source verb (#390 issue
/// comment: "like the `source` command in shell"). Restarts the sandbox
/// agent's ACP session so SOUL.md / AGENTS.md re-load; NOTE it also resets the
/// conversation (the resident session IS the conversation memory).
async fn restart_master_agent(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    match sandbox_bridge_request(&state, reqwest::Method::POST, "/v1/agent/restart", None).await {
        Ok(v) => {
            let evt = ApiAuditEvent {
                id: format!("e-agent-restart-{}", now_unix()),
                ts: now_ts_hms(),
                actor_id: "master".into(),
                actor: "master".into(),
                kind: "agent.restart".into(),
                detail: "agent re-sourced (fresh ACP session; context files re-read)".into(),
                chip: "persona".into(),
                sev: "ok".into(),
                tx_hash: None,
                audit_envelope_hashes: None,
            };
            push_audit(&state, evt).await;
            (axum::http::StatusCode::OK, Json(v)).into_response()
        }
        Err(e) => {
            let status = if e.starts_with("sandbox_unconfigured") {
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            } else {
                axum::http::StatusCode::BAD_GATEWAY
            };
            (status, Json(serde_json::json!({ "error": e }))).into_response()
        }
    }
}

/// `GET /v1/master/agent/context` — the VIEW leg (#390 acceptance 1): the LIVE
/// context files shaping the bound agent (SOUL.md, AGENTS.md, the locked
/// agent-terrier.md base layer, config.yaml redacted), read from the sandbox.
/// An unconfigured sandbox is a legit absent state (`configured: false`), not
/// an error; an unreachable configured one IS an error (502).
async fn get_master_agent_context(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    if state.sandbox_bridge_url.is_none() {
        return (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({ "configured": false, "files": [] })),
        )
            .into_response();
    }
    match sandbox_bridge_request(&state, reqwest::Method::GET, "/v1/context/files", None).await {
        Ok(v) => {
            let files = v.get("files").cloned().unwrap_or(serde_json::json!([]));
            (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({ "configured": true, "files": files })),
            )
                .into_response()
        }
        Err(e) => (
            axum::http::StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": e })),
        )
            .into_response(),
    }
}

async fn plant_master_memory(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<MasterMemoryPlantRequest>,
) -> axum::response::Response {
    match plant_master_memory_inner(&state, req).await {
        Ok(resp) => (axum::http::StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

/// Core plant logic. Returns the typed `MasterMemoryPlantResponse` (real chain or in-memory
/// fallback) or an `(HTTP status, reason)` for partial-config / not-logged-in
/// (409) and real-worker-failure (502). The handler maps it to a response; tests
/// call this directly to assert the typed counts.
async fn plant_master_memory_inner(
    state: &SharedUiBridgeState,
    req: MasterMemoryPlantRequest,
) -> Result<MasterMemoryPlantResponse, (axum::http::StatusCode, String)> {
    // #390 — the `persona` namespace is RESERVED: its single writer is the
    // daemon persona module (versioned, validated, master-authored). A plant
    // (or an inbox accept riding the plant) into it would bypass the edit-time
    // validation + version rotation, so it is rejected outright.
    if let Some(e) = req.entries.iter().find(|e| e.ns == PERSONA_NAMESPACE) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!(
                "persona_ns_reserved: entry `{}` targets the reserved `{PERSONA_NAMESPACE}` \
                 namespace — personas are edited via /v1/master/persona, never planted",
                e.key
            ),
        ));
    }
    let ctx = real_memory_ctx(state).await.map_err(|reason| {
        tracing::warn!("plant_master_memory: {reason}");
        (axum::http::StatusCode::CONFLICT, reason)
    })?;

    let mut planted = 0usize;
    let mut skipped = 0usize;
    let mut taxonomy_status = String::from("unconfigured");

    if let Some(ctx) = ctx {
        // REAL chain — read-modify-write per namespace under a plant lock so a
        // restart-stale cache or a concurrent plant can NEVER drop durable
        // entries (codex finding 1). Each namespace write MERGES the current
        // durable blob with the request, so the per-namespace JSON array grows
        // monotonically instead of last-writer-wins overwriting.
        let _plant_guard = state.plant_lock.lock().await;
        let client = reqwest::Client::new();

        // Hash every request entry once, then group by namespace.
        let mut by_ns: std::collections::BTreeMap<String, Vec<ApiMemoryEntry>> =
            std::collections::BTreeMap::new();
        for mut e in req.entries {
            if e.content_hash.is_empty() {
                e.content_hash = e.compute_hash();
            }
            by_ns.entry(e.ns.clone()).or_default().push(e);
        }

        // STS creds (memory role) minted once, reused across namespaces.
        let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
            &ctx.broker,
            &ctx.j1,
            &ctx.role_arn,
            &ctx.region,
        )
        .await
        .map_err(|e| {
            (
                axum::http::StatusCode::BAD_GATEWAY,
                format!("STS relay: {e}"),
            )
        })?;

        let mut committed: Vec<ApiMemoryEntry> = Vec::new();
        for (ns, entries) in &by_ns {
            // Read the durable blob FIRST. Ok(None) = brand-new namespace;
            // Err = a real worker/transport error → ABORT this plant rather than
            // overwrite durable data we failed to read (the finding-1 footgun).
            let durable = match memory_get_ns_real(&client, &ctx, &creds, ns).await {
                Ok(opt) => opt.unwrap_or_default(),
                Err(e) => {
                    return Err((
                        axum::http::StatusCode::BAD_GATEWAY,
                        format!(
                            "plant aborted: durable read of memory:{ns} failed ({e}) — not overwriting"
                        ),
                    ));
                }
            };
            let (merged, newly) = merge_stored_entries(ns, durable, entries);
            if let Err(e) = memory_put_ns_real(&client, &ctx, &creds, ns, &merged).await {
                return Err((
                    axum::http::StatusCode::BAD_GATEWAY,
                    format!("plant aborted: write of memory:{ns} failed: {e}"),
                ));
            }
            planted += newly;
            skipped += entries.len().saturating_sub(newly);
            committed.extend(entries.iter().cloned());
        }

        // Mirror the committed entries into the in-memory cache (a secondary
        // index for the list/detail fallback + same-session dedup); durable S3
        // remains the source of truth.
        {
            let mut cache = state.master_memory.write().await;
            for e in committed {
                cache.insert(e.content_hash.clone(), e);
            }
        }

        // Reconcile the durable taxonomy LAST, as a read-modify-write MERGE so a
        // plant ADDS its namespaces without ever dropping an authored taxonomy
        // (#207 item 1A) — categories_from_cache only knows planted namespaces.
        // A configured store FAILURE is surfaced as an explicit partial-success
        // status (codex finding 2) — the memory blobs ARE durable, but the
        // category index would be stale, so the operator must know to retry
        // rather than see a silent success.
        taxonomy_status = match real_config_ctx(state).await {
            Ok(Some(cfg)) => {
                let cache_cats = categories_from_cache(state).await;
                match reconcile_taxonomy(&client, &cfg, &cache_cats).await {
                    Ok(_) => "ok".to_string(),
                    Err(e) => {
                        tracing::error!(
                            "plant_master_memory: taxonomy reconcile FAILED (memory durable; \
                             category index stale — retry the plant): {e}"
                        );
                        format!("failed: {e}")
                    }
                }
            }
            Ok(None) => "unconfigured".to_string(),
            Err(e) => {
                tracing::warn!(
                    "plant_master_memory: config-context unavailable (taxonomy skipped): {e}"
                );
                format!("skipped: {e}")
            }
        };
    } else {
        // In-memory fallback (dev / no infra) — content-hash dedup.
        let mut mem = state.master_memory.write().await;
        for mut e in req.entries {
            let hash = if e.content_hash.is_empty() {
                e.compute_hash()
            } else {
                e.content_hash.clone()
            };
            e.content_hash = hash.clone();
            if let std::collections::hash_map::Entry::Vacant(slot) = mem.entry(hash) {
                slot.insert(e);
                planted += 1;
            } else {
                skipped += 1;
            }
        }
    }

    let total = state.master_memory.read().await.len();
    if planted > 0 {
        let evt = ApiAuditEvent {
            id: format!("e-mem-plant-{}", now_unix()),
            ts: now_ts_hms(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "memory.write".into(),
            detail: format!("planted preserved memory · {planted} entries · {skipped} duplicates"),
            chip: "memory".into(),
            sev: "ok".into(),
            tx_hash: None,
            audit_envelope_hashes: None,
        };
        push_audit(state, evt).await;
    }
    Ok(MasterMemoryPlantResponse {
        planted,
        skipped,
        total,
        taxonomy_status,
    })
}

// ─── #207 item 1A: config-init entry point A (default-preset bootstrap) ──────

/// One bundled preset, flattened for the wire (the daemon's `MemoryCategory`
/// shape so the UI reuses its category renderer).
#[derive(Serialize)]
struct PresetView {
    id: String,
    label: String,
    description: String,
    categories: Vec<MemoryCategory>,
}

fn preset_categories(p: &crate::presets::ConfigPreset) -> Vec<MemoryCategory> {
    p.categories
        .iter()
        .map(|(ns, label)| MemoryCategory {
            ns: (*ns).to_string(),
            label: (*label).to_string(),
        })
        .collect()
}

/// `GET /v1/master/config/presets` → the bundled default taxonomy presets + the
/// shipped default id (#207 item 1A). Read-only, no session required — these are
/// public bundled defaults (catalog ≠ policy: the presets carry categories, never
/// a tenant's grants).
async fn list_config_presets() -> axum::response::Response {
    let presets: Vec<PresetView> = crate::presets::bundled_presets()
        .iter()
        .map(|p| PresetView {
            id: p.id.to_string(),
            label: p.label.to_string(),
            description: p.description.to_string(),
            categories: preset_categories(p),
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "default_id": crate::presets::DEFAULT_PRESET_ID,
            "presets": presets,
        })),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct InitConfigRequest {
    /// Preset id to author; empty ⇒ the shipped default (rich adult-household).
    #[serde(default)]
    pub preset_id: String,
}

#[derive(Debug, Serialize)]
pub struct InitConfigResponse {
    /// The preset actually authored (echoes the resolved default for an empty id).
    pub preset_id: String,
    /// `"ok"` (durable `config/memory-taxonomy.enc` written) or `"cached"` (Config
    /// unconfigured — authored into the in-memory mirror only, dev/no-infra).
    pub taxonomy_status: String,
    /// The merged category set now in effect (authored ∪ any pre-existing).
    pub categories: Vec<MemoryCategory>,
}

/// `POST /v1/master/config/init` → author the memory-types taxonomy from a
/// bundled default preset (#207 item 1A, config-init entry point A). This writes
/// the category INDEX, not scope grants — it is master-self (operator == actor;
/// the broker skips the on-chain scope check, #195), the same posture as the
/// plant's taxonomy reconcile. Scope grants are K11-gated and land with
/// auto-distribute (#207 item 5); entry point B (NL → COMPILE) is #207 item 1B.
///
/// Idempotent: re-running merges (never clobbers) so a second init or a later
/// plant only adds namespaces.
async fn init_config_default(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<InitConfigRequest>,
) -> axum::response::Response {
    match init_config_default_inner(&state, &req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn init_config_default_inner(
    state: &SharedUiBridgeState,
    req: &InitConfigRequest,
) -> Result<InitConfigResponse, (StatusCode, String)> {
    let preset = crate::presets::resolve_preset(&req.preset_id).ok_or((
        StatusCode::BAD_REQUEST,
        format!("unknown preset_id: {}", req.preset_id),
    ))?;
    let authored = preset_categories(preset);

    let (taxonomy_status, categories) = match real_config_ctx(state).await {
        Ok(Some(cfg)) => {
            // REAL chain: read-modify-write MERGE into the durable, encrypted Config
            // store. A config worker failure (unreachable / S3 error) is a HARD error
            // — we author REAL durable data or fail loud. NO in-memory fallback that
            // masks a broken store (#201 finding-2): the operator must fix the Config
            // data class (provision the bucket + role, deploy/repair the worker).
            let client = reqwest::Client::new();
            let merged = reconcile_taxonomy(&client, &cfg, &authored)
                .await
                .map_err(|e| {
                    (
                        StatusCode::BAD_GATEWAY,
                        format!(
                            "taxonomy authoring failed — the Config data class must be healthy \
                             (config worker reachable + its bucket/role provisioned with S3 \
                             Get/Put/List on bots/<actor>/config/*): {e}"
                        ),
                    )
                })?;
            ("ok".to_string(), merged)
        }
        // No `--config-url` configured AT ALL: the explicit dev/no-infra mode —
        // author into the in-memory mirror so the local UI works WITHOUT a config
        // worker. This is NOT a degrade of a configured store (that fails loud
        // above); it is the honest absence of one.
        Ok(None) => {
            let existing = state
                .authored_taxonomy
                .read()
                .await
                .clone()
                .map(|t| t.categories)
                .unwrap_or_default();
            ("cached".to_string(), merge_categories(existing, &authored))
        }
        // Partial config (config-url set but role missing) / no session — a real
        // misconfiguration the operator must fix; fail loud.
        Err(e) => return Err((StatusCode::CONFLICT, format!("config not ready: {e}"))),
    };

    // Write-through the in-memory mirror in both paths (the unconfigured home,
    // and a cache aligned with durable Config for the real path).
    *state.authored_taxonomy.write().await = Some(MemoryTaxonomy {
        version: 1,
        categories: categories.clone(),
    });

    // Audit the authoring action. The taxonomy is the Config data class; the
    // closest existing audit chip is `memory` (it IS the memory-types taxonomy).
    let evt = ApiAuditEvent {
        id: format!("e-cfg-init-{}", now_unix()),
        ts: now_ts_hms(),
        actor_id: "master".into(),
        actor: "master".into(),
        kind: "config.taxonomy".into(),
        detail: format!(
            "authored taxonomy · preset {} · {} categories",
            preset.id,
            categories.len()
        ),
        chip: "memory".into(),
        sev: "ok".into(),
        tx_hash: None,
        audit_envelope_hashes: None,
    };
    push_audit(state, evt).await;

    Ok(InitConfigResponse {
        preset_id: preset.id.to_string(),
        taxonomy_status,
        categories,
    })
}

// ─── #207 items 5 + 7: classification (cred-categorize + auto-distribute) ────
//
// The CLASSIFY BRIDGE. Two paths, same deterministic catalog data:
//   • worker (audited) — when `--classify-url` + a real session: mint a master-self
//     `Classify` cap → `POST /v1/classify/tag`. Picks up signed vendor overlays + audit.
//   • local tier-0 — otherwise: the bundled `agentkeys-catalog` in-process
//     (deterministic, free, no infra). This IS the intended tier-0 (#178 §8.1).
//
// Determinism guardrail (#178 §5): TAG returns a category + sensitivity, NEVER
// allow/deny. The sensitivity comes from the CATALOG floor (not a vendor/telemetry
// prior, #207 §3 invariant 2). `propose` proposes scopes; it NEVER writes one —
// the confirm/grant path (the existing K11-gated `update_scope`) is the only writer,
// so an unconfirmed sensitive category produces NO scope grant by construction.

/// Process-wide bundled catalog (tier-0). Built once.
fn bundled_catalog() -> &'static agentkeys_catalog::Catalog {
    static CATALOG: std::sync::OnceLock<agentkeys_catalog::Catalog> = std::sync::OnceLock::new();
    CATALOG.get_or_init(agentkeys_catalog::Catalog::bundled)
}

/// Normalize/validate a data-class string to the cap's snake_case set. Defaults
/// to `credentials` (the common cred-categorize case) for an empty value.
fn normalize_data_class(s: &str) -> Result<&'static str, String> {
    match s.trim().to_lowercase().as_str() {
        "" | "credentials" | "cred" => Ok("credentials"),
        "memory" => Ok("memory"),
        "config" => Ok("config"),
        other => Err(format!("unknown data_class: {other}")),
    }
}

/// The auto-distribute gating tier for a category's sensitivity (#207 §3 inv. 2):
/// Safe → `auto` (auto-confirm + daily review); Sensitive → `k11` (explicit confirm).
/// The tier comes from the CATALOG floor, so a vendor/telemetry prior can't downgrade it.
fn gating_for(s: agentkeys_catalog::Sensitivity) -> ScopeGating {
    match s {
        agentkeys_catalog::Sensitivity::Safe => ScopeGating::Auto,
        agentkeys_catalog::Sensitivity::Sensitive => ScopeGating::K11,
    }
}

/// The signed `service` string a scope grant would be over: memory → `memory:<ns>`,
/// credentials/other → the lowercased entity (service id). Matches the cap layer.
fn service_for(data_class: &str, entity: &str) -> String {
    match data_class {
        "memory" => format!("memory:{}", entity.trim().to_lowercase()),
        _ => entity.trim().to_lowercase(),
    }
}

/// Mint a master-self `Classify` cap for `(data_class, entity)` via the broker.
async fn mint_master_classify_cap(
    client: &reqwest::Client,
    broker: &str,
    j1: &str,
    omni: &str,
    device_key_hash: &str,
    data_class: &str,
) -> Result<serde_json::Value, String> {
    let service = format!("classify:{data_class}");
    let resp = client
        .post(format!("{broker}/v1/cap/classify"))
        .bearer_auth(j1)
        .json(&serde_json::json!({
            "operator_omni": omni,
            "actor_omni": omni,
            "service": service,
            "device_key_hash": device_key_hash,
            "data_class": data_class,
            "ttl_seconds": 300,
        }))
        .send()
        .await
        .map_err(|e| format!("classify cap-mint transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "classify cap-mint {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("classify cap json: {e}"))
}

/// The audited worker TAG path. `Ok(None)` when `--classify-url` is unset (caller
/// falls back to the local tier-0); `Err` on a real failure (session/cap/worker).
async fn classify_via_worker(
    state: &SharedUiBridgeState,
    data_class: &str,
    entity: &str,
) -> Result<Option<agentkeys_catalog::Classification>, String> {
    let Some(classify_url) = state.classify_url.clone() else {
        return Ok(None);
    };
    let coords = resolve_session_coords(state).await?;
    let client = reqwest::Client::new();
    let cap = mint_master_classify_cap(
        &client,
        &coords.broker,
        &coords.j1,
        &coords.omni,
        &coords.device_key_hash,
        data_class,
    )
    .await?;
    let resp = client
        .post(format!("{classify_url}/v1/classify/tag"))
        .json(&serde_json::json!({ "cap": cap, "data_class": data_class, "entity": entity }))
        .send()
        .await
        .map_err(|e| format!("classify tag transport: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!(
            "classify tag {status}: {}",
            resp.text().await.unwrap_or_default()
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("classify tag json: {e}"))?;
    let classification = serde_json::from_value(body["classification"].clone())
        .map_err(|e| format!("classification parse: {e}"))?;
    Ok(Some(classification))
}

/// Classify an entity → category + sensitivity. For MEMORY the entity is a
/// namespace = a category, so its sensitivity is the catalog FLOOR (#207 item 8,
/// agent memory inheritance) — a deterministic local lookup. For credentials/config
/// the entity is a service: worker (audited) when configured + reachable, else the
/// bundled catalog tier-0 (same data, deterministic).
async fn classify_entity(
    state: &SharedUiBridgeState,
    data_class: &str,
    entity: &str,
) -> agentkeys_catalog::Classification {
    if data_class == "memory" {
        return bundled_catalog().classify_namespace(entity);
    }
    if state.classify_url.is_some() {
        match classify_via_worker(state, data_class, entity).await {
            Ok(Some(c)) => return c,
            Ok(None) => {}
            Err(e) => tracing::warn!("classify worker path failed, using local tier-0: {e}"),
        }
    }
    bundled_catalog().tag(entity)
}

#[derive(Debug, Deserialize)]
pub struct ClassifyTagRequest {
    #[serde(default)]
    pub data_class: String,
    pub entity: String,
}

/// `POST /v1/master/classify/tag` (#207 item 7 — cred auto-categorize). Classify a
/// minted credential's service (or any entity) → its category + sensitivity, so the
/// master can confirm a `cred:<service>` grant. Read-only; never writes scope.
async fn classify_tag(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ClassifyTagRequest>,
) -> axum::response::Response {
    let data_class = match normalize_data_class(&req.data_class) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e })),
            )
                .into_response()
        }
    };
    if req.entity.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "entity required" })),
        )
            .into_response();
    }
    let c = classify_entity(&state, data_class, &req.entity).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "data_class": data_class,
            "entity": req.entity.trim().to_lowercase(),
            "service": service_for(data_class, &req.entity),
            "classification": c,
            "audited": state.classify_url.is_some(),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct SurfaceItem {
    #[serde(default)]
    pub data_class: String,
    pub entity: String,
}

#[derive(Debug, Deserialize)]
pub struct ProposeRequest {
    #[serde(default)]
    pub actor_id: String,
    pub surface: Vec<SurfaceItem>,
}

/// One proposed scope grant. `gating` is the sensitivity tier from the CATALOG:
/// `auto` (Safe → auto-confirm + surface in the daily review) | `k11` (Sensitive →
/// explicit per-grant K11 confirm). NEVER granted here — `propose` only proposes.
#[derive(Debug, Serialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ProposedScope {
    pub data_class: String,
    pub entity: String,
    pub service: String,
    pub category: String,
    pub sensitivity: agentkeys_catalog::Sensitivity,
    pub gating: ScopeGating,
    pub confidence: f32,
}

/// The #207 §3 grant-gating tier for a proposed scope: `auto` (Safe →
/// auto-confirm + daily review) | `k11` (Sensitive → explicit per-grant K11
/// confirm). An enum (not a bare str) so the generated TS carries the union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ts_rs::TS)]
#[serde(rename_all = "snake_case")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum ScopeGating {
    Auto,
    K11,
}

/// `POST /v1/master/classify/propose` (#207 item 5 — connect-time auto-distribute).
/// Classify an agent's surface (the memory namespaces it reads + the cred services
/// it uses) and PROPOSE scopes, sensitivity-tiered. This writes NOTHING: safe
/// proposals are `auto` (the UI can confirm a reviewed set in one gesture); sensitive
/// ones are `k11` (explicit per-grant confirm). The grant itself is the existing
/// K11-gated `update_scope` path — so an unconfirmed sensitive category produces NO
/// scope grant (the load-bearing #207 §3 invariant 2, true by construction).
async fn classify_propose(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<ProposeRequest>,
) -> axum::response::Response {
    let mut proposals: Vec<ProposedScope> = Vec::new();
    for item in &req.surface {
        let data_class = match normalize_data_class(&item.data_class) {
            Ok(d) => d,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({ "error": e })),
                )
                    .into_response()
            }
        };
        if item.entity.trim().is_empty() {
            continue;
        }
        let c = classify_entity(&state, data_class, &item.entity).await;
        let gating = gating_for(c.sensitivity);
        proposals.push(ProposedScope {
            data_class: data_class.to_string(),
            entity: item.entity.trim().to_lowercase(),
            service: service_for(data_class, &item.entity),
            category: c.category,
            sensitivity: c.sensitivity,
            gating,
            confidence: c.confidence,
        });
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "actor_id": req.actor_id, "proposals": proposals })),
    )
        .into_response()
}

// ─── #207: master CREDENTIALS surface (same abstraction as memory) ───────────
//
// Credentials are a first-class data class in the app, mirroring memory: the
// memory list resolves namespaces → categories (the taxonomy); the credentials
// list resolves stored services → categories (the catalog). Both are
// list-then-categorize over the master's own real data. Real data or a loud
// failure — no in-memory stand-in (the unconfigured dev case is an honest empty).

struct RealCredCtx {
    broker: String,
    cred_url: String,
    role_arn: String,
    region: String,
    j1: String,
    omni: String,
    device_key_hash: String,
}

/// Resolve the cred-worker context from env (`AGENTKEYS_WORKER_CRED_URL` +
/// `VAULT_ROLE_ARN`, which the daemon's launcher sources from
/// operator-workstation.env) + the master session. `Ok(None)` when the cred
/// worker isn't configured (dev/no-infra). A partial config (URL set but role
/// missing) fails loud (issue #90 discipline).
async fn real_cred_ctx(state: &UiBridgeState) -> Result<Option<RealCredCtx>, String> {
    let cred_url = match std::env::var("AGENTKEYS_WORKER_CRED_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => return Ok(None),
    };
    let role_arn = std::env::var("VAULT_ROLE_ARN")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or("real cred: AGENTKEYS_WORKER_CRED_URL set but VAULT_ROLE_ARN missing")?;
    let c = resolve_session_coords(state).await?;
    Ok(Some(RealCredCtx {
        broker: c.broker,
        cred_url,
        role_arn,
        region: c.region,
        j1: c.j1,
        omni: c.omni,
        device_key_hash: c.device_key_hash,
    }))
}

/// A categorized credential service — the cred parallel to `MemoryCategory`:
/// the service id + its catalog category + sensitivity (so the UI groups creds
/// by category exactly like memory namespaces).
#[derive(Debug, Serialize)]
pub struct CredService {
    pub service: String,
    pub category: String,
    pub sensitivity: agentkeys_catalog::Sensitivity,
}

/// `GET /v1/master/credentials` — list the master's stored credential services
/// (cred worker `/v1/cred/list`), each categorized via the catalog. The
/// per-data-class parallel to `GET /v1/master/memory`. Unconfigured (no cred
/// worker) → empty (honest dev); a configured-but-broken worker → 502.
async fn list_master_credentials(
    State(state): State<SharedUiBridgeState>,
) -> axum::response::Response {
    match list_master_credentials_inner(&state).await {
        Ok(creds) => (
            StatusCode::OK,
            Json(serde_json::json!({ "credentials": creds })),
        )
            .into_response(),
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn list_master_credentials_inner(
    state: &SharedUiBridgeState,
) -> Result<Vec<CredService>, (StatusCode, String)> {
    let ctx = match real_cred_ctx(state).await {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(Vec::new()), // no cred worker configured (dev) → empty
        Err(e) => return Err((StatusCode::CONFLICT, format!("cred not ready: {e}"))),
    };
    let client = reqwest::Client::new();
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "cred-fetch",
        "credentials",
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred cap-mint: {e}")))?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay (cred): {e}")))?;
    let resp = client
        .post(format!("{}/v1/cred/list", ctx.cred_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        .json(&serde_json::json!({ "cap": cap }))
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred list transport: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "cred list {status}: {}",
                resp.text().await.unwrap_or_default()
            ),
        ));
    }
    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred list json: {e}")))?;
    let services: Vec<String> = body["services"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::with_capacity(services.len());
    for svc in services {
        let c = classify_entity(state, "credentials", &svc).await;
        out.push(CredService {
            service: svc,
            category: c.category,
            sensitivity: c.sensitivity,
        });
    }
    out.sort_by(|a, b| {
        (a.category.clone(), a.service.clone()).cmp(&(b.category.clone(), b.service.clone()))
    });
    Ok(out)
}

#[derive(Debug, Deserialize)]
pub struct StoreCredRequest {
    pub service: String,
    pub secret: String,
}

/// `POST /v1/master/credentials/store` — vault a master credential (mint a
/// master-self `cred-store` cap → STS → cred worker `/v1/cred/store`). The
/// credential parallel to the memory plant. Real durable write or a loud failure.
async fn store_master_credential(
    State(state): State<SharedUiBridgeState>,
    Json(req): Json<StoreCredRequest>,
) -> axum::response::Response {
    let service = req.service.trim().to_lowercase();
    if service.is_empty() || service.len() > 64 || req.secret.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "service (1..=64) and secret are required" })),
        )
            .into_response();
    }
    let ctx = match real_cred_ctx(&state).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": "no cred worker configured (set AGENTKEYS_WORKER_CRED_URL + VAULT_ROLE_ARN)" })),
            )
                .into_response()
        }
        Err(e) => {
            return (StatusCode::CONFLICT, Json(serde_json::json!({ "error": format!("cred not ready: {e}") }))).into_response()
        }
    };
    match store_master_credential_inner(&ctx, &service, &req.secret).await {
        Ok(category) => {
            let evt = ApiAuditEvent {
                id: format!("e-cred-store-{}", now_unix()),
                ts: now_ts_hms(),
                actor_id: "master".into(),
                actor: "master".into(),
                kind: "credential.store".into(),
                detail: format!("vaulted credential · {service} · {category}"),
                chip: "creds".into(),
                sev: "ok".into(),
                tx_hash: None,
                audit_envelope_hashes: None,
            };
            push_audit(&state, evt).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({ "ok": true, "service": service, "category": category })),
            )
                .into_response()
        }
        Err((status, reason)) => {
            (status, Json(serde_json::json!({ "error": reason }))).into_response()
        }
    }
}

async fn store_master_credential_inner(
    ctx: &RealCredCtx,
    service: &str,
    secret: &str,
) -> Result<String, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let client = reqwest::Client::new();
    let cap = mint_master_cap(
        &ctx.broker,
        &ctx.j1,
        &ctx.omni,
        &ctx.device_key_hash,
        "cred-store",
        service,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("cred cap-mint: {e}")))?;
    let creds = agentkeys_provisioner::fetch_via_broker_default_ttl(
        &ctx.broker,
        &ctx.j1,
        &ctx.role_arn,
        &ctx.region,
    )
    .await
    .map_err(|e| (StatusCode::BAD_GATEWAY, format!("STS relay (cred): {e}")))?;
    let resp = client
        .post(format!("{}/v1/cred/store", ctx.cred_url))
        .header("x-aws-access-key-id", creds.access_key_id)
        .header("x-aws-secret-access-key", creds.secret_access_key)
        .header("x-aws-session-token", creds.session_token)
        // Crate-owned body shape (#204) — a drifted field is a compile error.
        .json(&agentkeys_backend_client::CredStoreBody {
            cap,
            plaintext_b64: STANDARD.encode(secret.as_bytes()),
        })
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("cred store transport: {e}"),
            )
        })?;
    if !resp.status().is_success() {
        let status = resp.status();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "cred store {status}: {}",
                resp.text().await.unwrap_or_default()
            ),
        ));
    }
    Ok(bundled_catalog().tag(service).category)
}

async fn push_audit(state: &SharedUiBridgeState, evt: ApiAuditEvent) {
    let mut buf = state.audit.write().await;
    if buf.len() == AUDIT_BUFFER_CAP {
        buf.pop_front();
    }
    buf.push_back(evt.clone());
    drop(buf);
    // Ignore send errors — broadcast Sender returns Err when there
    // are no subscribers, which is the normal case until the UI connects.
    let _ = state.audit_tx.send(evt);
}

// ─── Tests ─────────────────────────────────────────────────────────────
//
// These tests exercise the begin/finish state machine without a real
// browser. They use webauthn-rs's `SoftPasskey` test helper so the
// attestation chain is real (not stubbed), but everything happens
// in-process — no network, no platform authenticator, no Touch ID.
//
// Coverage focus per PR-A's cargo-llvm-cov gate:
//   - happy-path begin → finish round-trip
//   - finish with a stale / never-issued user_id → "no-pending" error
//   - finish with a malformed credential JSON  → "credential-malformed" error
//   - finish that tries to replay a consumed user_id → "no-pending" (consumed at finish)
//   - begin with empty username → "missing-username" error
//
// Run: `cargo test -p agentkeys-daemon --lib ui_bridge`
//      `cargo llvm-cov -p agentkeys-daemon --lib ui_bridge`

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_worker_url_reasons_the_gateway_per_stack() {
        // The four operator stacks — mirrors the env files' `weixin<suffix>.<zone>`
        // (scripts/operator-workstation*.env) so the daemon reasons the URL from
        // the broker instead of a hardcoded per-stack env var.
        let cases = [
            ("https://broker.litentry.org", "https://weixin.litentry.org"),
            (
                "https://test-broker.litentry.org",
                "https://weixin-test.litentry.org",
            ),
            (
                "https://broker-test-2.litentry.org",
                "https://weixin-test-2.litentry.org",
            ),
            (
                "https://broker-base.litentry.org",
                "https://weixin-base.litentry.org",
            ),
        ];
        for (broker, want) in cases {
            assert_eq!(
                derive_worker_url(broker, "weixin").as_deref(),
                Some(want),
                "broker {broker}"
            );
        }
        // The helper generalizes to any co-located worker.
        assert_eq!(
            derive_worker_url("https://broker.litentry.org", "memory").as_deref(),
            Some("https://memory.litentry.org")
        );
        // A scheme-less / trailing-path broker host still resolves.
        assert_eq!(
            derive_worker_url("broker-base.litentry.org/", "weixin").as_deref(),
            Some("https://weixin-base.litentry.org")
        );
        // A local/dev broker (bare IP / localhost / single label) → None, so the
        // caller reports not-configured rather than fabricating a bogus host.
        for local in [
            "http://127.0.0.1:8081",
            "http://localhost:8081",
            "https://broker",
        ] {
            assert_eq!(derive_worker_url(local, "weixin"), None, "local {local}");
        }
    }

    /// #339 — the security distinction the inbox grant rests on: a `memory:<ns>`
    /// grant confers READ (the master's shared canonical memory) but NEVER write,
    /// and an `inbox:<ns>` grant confers WRITE (suggest into the master's inbox) but
    /// NEVER read. Granting read never grants write (`keccak("inbox:<ns>") !=
    /// keccak("memory:<ns>")`) — the delegate never writes the master's shared memory
    /// directly. An unknown service (e.g. `cred:<svc>`) is preserved verbatim for the
    /// panel's set-replace commit.
    #[test]
    fn classify_scope_hashes_separates_shared_read_from_inbox_write() {
        use agentkeys_core::device_crypto::keccak256;
        let mem = keccak256(b"memory:travel");
        let inbox = keccak256(b"inbox:travel");
        let cred = keccak256(b"cred:openrouter");

        // memory grant → READ (shared canonical), never inbox-write.
        let (map, unknown) = classify_scope_hashes(&[mem]);
        let m = map.expect("memory grant present");
        assert!(
            m["travel"].read && !m["travel"].write,
            "a memory grant is shared-READ only — never inbox-write"
        );
        assert!(unknown.is_empty());

        // inbox grant → WRITE (suggest to inbox), never shared read.
        let (map, _) = classify_scope_hashes(&[inbox]);
        let m = map.expect("inbox grant present");
        assert!(
            m["travel"].write && !m["travel"].read,
            "an inbox grant is WRITE/suggest only — never shared read"
        );

        // both grants on one ns → read + write, merged.
        let (map, _) = classify_scope_hashes(&[mem, inbox]);
        let m = map.unwrap();
        assert!(m["travel"].read && m["travel"].write);

        // unknown service (cred) is preserved verbatim, never in the named map.
        let (map, unknown) = classify_scope_hashes(&[cred]);
        assert!(map.is_none());
        assert_eq!(unknown, vec![format!("0x{}", hex::encode(cred))]);
    }

    /// The audit decode view must show the GRANT SET, not raw keccak hashes:
    /// `memory:<ns>` / `inbox:<ns>` / cred services decode by name; an unknown hash
    /// passes through labeled (never silently dropped).
    #[test]
    fn annotate_service_names_decodes_the_grant_set() {
        use agentkeys_core::device_crypto::keccak256;
        let h = |s: &str| format!("0x{}", hex::encode(keccak256(s.as_bytes())));
        let map = scope_name_map(&["openrouter".to_string()]);
        let mut decoded = serde_json::json!({
            "envelope": { "op_body": { "service_ids": [
                h("memory:family"), h("inbox:travel"), h("cred:openrouter"), "0xdeadbeef"
            ] } }
        });
        annotate_service_names(&mut decoded, &map);
        let names = &decoded["envelope"]["op_body"]["service_names"];
        assert_eq!(names[0], "memory:family");
        assert_eq!(names[1], "inbox:travel");
        assert_eq!(names[2], "cred:openrouter");
        assert!(names[3]
            .as_str()
            .unwrap()
            .starts_with("unknown · 0xdeadbeef"));
    }

    /// #214: a broker PendingBinding row (post-claim, §10.2) maps to the web UI's
    /// PairingRequest shape — label→agent, requested_scope→RequestedPerm[],
    /// device_pubkey→dpub. The device key is surfaced for display only, never as
    /// a secret, and the HDKD derivation path is reconstructed from the label.
    #[test]
    fn pending_binding_maps_to_pairing_request() {
        let row = serde_json::json!({
            "request_id": "req-abc123def456",
            "child_omni": "0xchildomni",
            "operator_omni": "0xmasteromni",
            "label": "demo-agent",
            "requested_scope": "memory:travel,memory:family",
            "device_pubkey": "0x04aabbccddeeff00112233445566778899aabbcc",
            "device_key_hash": "0x6d02e352b9bd71d3aa35677c35492bfdc39bacda89cc7d0506d31e2754abf2a5",
            "pop_sig": "0xsignaturedeadbeef0011223344556677",
            "pairing_code": "bPe5Y8qNAdReal0neTimeCode",
            "created_at": 1_700_000_000_i64,
            "expires_at": 1_700_000_600_i64,
        });
        let pr = pending_binding_to_request(&row);
        assert_eq!(pr["id"], "req-abc123def456");
        assert_eq!(pr["agent"], "demo-agent");
        assert_eq!(pr["derivation"], "//demo-agent");
        assert_eq!(pr["dpubFull"], "0x04aabbccddeeff00112233445566778899aabbcc");
        // #224 — the cross-verifiable device identity must be surfaced full.
        assert_eq!(
            pr["deviceKeyHash"],
            "0x6d02e352b9bd71d3aa35677c35492bfdc39bacda89cc7d0506d31e2754abf2a5"
        );
        // #224 — pairCode is the agent's REAL one-time code (NOT the request_id),
        // and start/expiry pass through verbatim for the card's countdown.
        assert_eq!(pr["pairCode"], "bPe5Y8qNAdReal0neTimeCode");
        assert_eq!(pr["requestedAt"], 1_700_000_000_i64);
        assert_eq!(pr["expiresAt"], 1_700_000_600_i64);
        let requested = pr["requested"].as_array().expect("requested is an array");
        assert_eq!(requested.len(), 2, "two scope tokens");
        assert_eq!(requested[0]["cap"], "memory");
        assert_eq!(requested[0]["ns"][0], "travel");
        assert_eq!(requested[1]["ns"][0], "family");
        // A memory-scoped claim is a sandbox DELEGATE, never a device.
        assert_eq!(pr["isDevice"], false);
        assert_eq!(pr["vendor"], "agent");
        assert_eq!(pr["runtime"], "hermes");
    }

    /// #408 D6 — a claim whose requested_scope is ONLY channel-pub/sub grants
    /// maps with `isDevice: true` (the same `scope_is_device_only` predicate the
    /// broker's D9 no-spawn gate uses), and the declared placeholders stop
    /// claiming a sandbox/hermes runtime the device does not have. The web app
    /// splits the pairing page (delegates) from the channel page (devices) on
    /// this flag.
    #[test]
    fn pending_binding_channel_only_scope_maps_to_device_request() {
        let row = serde_json::json!({
            "request_id": "req-device01",
            "child_omni": "0xchildomni",
            "operator_omni": "0xmasteromni",
            "label": "cam-frontdoor",
            "requested_scope": "channel-pub:cam-frontdoor,channel-sub:kitchen-display",
            "device_pubkey": "0x04aabbccddeeff00112233445566778899aabbcc",
            "device_key_hash": "0xdkh",
            "pop_sig": "0xsig",
            "pairing_code": "code",
            "created_at": 1_700_000_000_i64,
            "expires_at": 1_700_000_600_i64,
        });
        let pr = pending_binding_to_request(&row);
        assert_eq!(pr["isDevice"], true);
        assert_eq!(pr["vendor"], "device");
        assert_eq!(pr["device"], "channel-endpoint device (K10)");
        assert_eq!(pr["runtime"], "none — channel endpoint (no runtime)");
        // The channel tokens still flow into the accept card's picker rows.
        let requested = pr["requested"].as_array().expect("requested array");
        assert_eq!(requested[0]["cap"], "channel-pub");
        assert_eq!(requested[0]["ns"][0], "cam-frontdoor");
        assert_eq!(requested[1]["cap"], "channel-sub");
        assert_eq!(requested[1]["ns"][0], "kitchen-display");
        // Mixed scope (a channel grant + memory) is a DELEGATE (spec: mixed =
        // delegate) — the device flag must not fire.
        let mut mixed = row.clone();
        mixed["requested_scope"] = serde_json::json!("channel-pub:cam,memory:travel");
        assert_eq!(pending_binding_to_request(&mixed)["isDevice"], false);
    }

    /// #404 channel registry — the id is the immutable on-chain anchor, so its
    /// shape is strict: lowercase [a-z0-9-], 1-48 chars, no edge hyphens.
    #[test]
    fn channel_id_validation() {
        assert!(valid_channel_id("cam-frontdoor"));
        assert!(valid_channel_id("a"));
        assert!(valid_channel_id("kitchen-display-2"));
        assert!(!valid_channel_id(""));
        assert!(!valid_channel_id("Cam")); // uppercase — ids hash LOWERCASED
        assert!(!valid_channel_id("-cam"));
        assert!(!valid_channel_id("cam-"));
        assert!(!valid_channel_id("cam frontdoor"));
        assert!(!valid_channel_id(&"x".repeat(49)));
    }

    /// #404 — the registry's reverse map recovers channel service NAMES from
    /// the on-chain keccak hashes (restart-proof naming), and `channel_holders`
    /// finds grant holders by name AND by hash (the delete-in-use guard).
    #[test]
    fn channel_registry_candidates_and_holders() {
        let reg = ChannelRegistry {
            version: 1,
            channels: vec![ApiChannel {
                id: "cam-frontdoor".into(),
                name: "Front door camera".into(),
                note: None,
                created_at: 0,
            }],
        };
        let cand = channel_service_candidates(&reg);
        let pub_hash = format!(
            "0x{}",
            hex::encode(agentkeys_core::device_crypto::keccak256(
                b"channel-pub:cam-frontdoor"
            ))
        );
        assert_eq!(
            cand.get(&pub_hash).map(String::as_str),
            Some("channel-pub:cam-frontdoor")
        );
        assert_eq!(cand.len(), 2, "pub + sub per registry channel");

        // Holders: one actor by NAME, one by on-chain HASH, one unrelated.
        let mk = |id: &str, label: &str| ApiActor {
            id: id.into(),
            omni: "0x1".into(),
            omni_hex: "0x1".into(),
            label: label.into(),
            role: "agent".into(),
            parent: None,
            derivation: String::new(),
            device: String::new(),
            device_pubkey: String::new(),
            last_active: String::new(),
            status: "ok".into(),
            vendor: String::new(),
            k11: false,
            device_key_hash: None,
            scope: None,
            scope_unknown_service_ids: None,
            payment_cap: None,
            time_window: None,
            services: None,
            account_address: None,
            account_type: None,
            preset_id: None,
            memory_ns: None,
        };
        let mut actors = HashMap::new();
        let mut by_name = mk("a1", "cam-by-name");
        by_name.services = Some(vec!["channel-pub:cam-frontdoor".into()]);
        actors.insert("a1".into(), by_name);
        let mut by_hash = mk("a2", "cam-by-hash");
        by_hash.scope_unknown_service_ids = Some(vec![pub_hash]);
        actors.insert("a2".into(), by_hash);
        let mut other = mk("a3", "unrelated");
        other.services = Some(vec!["memory:travel".into()]);
        actors.insert("a3".into(), other);

        let holders = channel_holders(&actors, "cam-frontdoor");
        assert_eq!(holders, vec!["cam-by-hash", "cam-by-name"]);
        assert!(channel_holders(&actors, "kitchen-display").is_empty());
    }

    /// #214: the pairing routes (poll / claim / register) require a configured
    /// broker — `make_state` has none, so every one fails closed with 503 rather
    /// than reaching the network. (Live broker behavior is the harness e2e.)
    #[tokio::test]
    async fn pairing_routes_fail_closed_without_a_broker() {
        let state = make_state();
        assert_eq!(
            list_pairing_requests(State(state.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            claim_pairing(
                State(state.clone()),
                Json(ClaimPairingRequest {
                    pairing_code: "PAIR-1234".into(),
                    label: "demo-agent".into(),
                    requested_scope: String::new(),
                }),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            register_pairing(
                State(state),
                Json(RegisterPairingRequest {
                    request_id: "req-1".into(),
                }),
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Pin the master-memory plant CONTRACT (the daemon's web API, owned by
    /// `agentkeys-protocol::web_api` and re-exported above) to the committed
    /// fixture that `suite-6-web-parity.sh` is gated against (issue #203 / the
    /// #206 parity ladder). The shared struct + route const are the source of
    /// truth; this test fails the moment they drift from the fixture, so a
    /// field rename or route change can't silently leave phase 6 green on the
    /// old path. The React frontend is NOT fixture-gated anymore (#275): it
    /// consumes the wasm-exported builder, so its half is compile-checked. If
    /// you change `ApiMemoryEntry` or the route on purpose, update
    /// `e2e/fixtures/web-api/master_memory_plant.json` to match (and the
    /// harness consumer is re-gated by the bash check).
    #[test]
    fn master_memory_plant_contract_matches_fixture() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../e2e/fixtures/web-api/master_memory_plant.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let fixture: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");

        assert_eq!(
            fixture["route"].as_str().expect("fixture.route"),
            MASTER_MEMORY_PLANT_ROUTE,
            "route const drifted from the web-api fixture"
        );

        let sample = ApiMemoryEntry {
            ns: "travel".into(),
            key: "probe".into(),
            title: "t".into(),
            bytes: 1,
            version: "v1".into(),
            updated: "2026-06-05".into(),
            preview: "p".into(),
            body: "b".into(),
            content_hash: String::new(),
            kind: ContextKind::Knowledge,
        };
        let mut got: Vec<String> = serde_json::to_value(&sample)
            .expect("entry serializes")
            .as_object()
            .expect("entry is an object")
            .keys()
            .cloned()
            .collect();
        got.sort();
        let want: Vec<String> = fixture["entry_keys"]
            .as_array()
            .expect("fixture.entry_keys")
            .iter()
            .map(|v| v.as_str().expect("entry_key is str").to_string())
            .collect();
        assert_eq!(
            got, want,
            "ApiMemoryEntry keys drifted from the web-api fixture — regenerate \
             e2e/fixtures/web-api/master_memory_plant.json + re-gate daemon.ts/suite-6-web-parity.sh"
        );
    }

    fn make_state() -> SharedUiBridgeState {
        build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            None,
            None, // #220 master_session_store — tests never persist to $HOME
        )
        .unwrap()
    }

    // ─── issue #220: master session persistence + rehydrate ─────────────────

    /// Like [`make_state`] but with `register_master_script` set, so handlers that
    /// shell out to chain helpers (e.g. `revoke_device` → `heima-device-revoke.sh`,
    /// resolved as a sibling) can run against a fake script in tests.
    fn make_state_with_script(register_master_script: String) -> SharedUiBridgeState {
        build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(register_master_script),
            None,
        )
        .unwrap()
    }

    /// A real-ish ui-bridge state (broker configured) with an optional on-disk
    /// master-session store — used by the #220 resolve/rehydrate tests.
    fn make_state_real(store: Option<MasterSessionStore>) -> SharedUiBridgeState {
        build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("https://broker.example".into()),
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None, // master_device_key_hash — deliberately UNSET (derivation path)
            None,
            store,
        )
        .unwrap()
    }

    fn persisted_record(omni: &str, j1_exp_unix: u64) -> PersistedMasterSession {
        PersistedMasterSession {
            schema: 1,
            wallet: "0xMASTERWALLET".into(),
            email: "master@example.com".into(),
            operator_omni: omni.to_string(),
            device_key_hash: agentkeys_core::device_crypto::device_key_hash_from_omni(omni)
                .unwrap(),
            j1: "eyJ.fake.jwt".into(),
            created_at_unix: master_session::now_unix(),
            j1_exp_unix,
        }
    }

    #[tokio::test]
    async fn resolve_session_coords_derives_device_hash_from_omni() {
        // No registered_master and no --master-device-key-hash flag, but a valid
        // session omni ⇒ the device hash is DERIVED keccak(operator_omni). So the
        // web loop needs neither a cached register nor the CLI flag after a restart.
        let state = make_state_real(None);
        let omni = format!("0x{}", "11".repeat(32));
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "m@x".into(),
            omni: omni.clone(),
            j1: "eyJ.fake.jwt".into(),
            wallet: "0xWALLET".into(),
        });
        let coords = resolve_session_coords(&state)
            .await
            .expect("coords resolve");
        let expected = agentkeys_core::device_crypto::device_key_hash_from_omni(&omni).unwrap();
        assert_eq!(coords.device_key_hash, expected);
        assert_eq!(coords.omni, omni);
    }

    #[tokio::test]
    async fn resolve_session_coords_distinguishes_expired_from_absent() {
        // No session AND nothing persisted ⇒ "no local master session" (onboard).
        let state = make_state_real(None);
        let e = match resolve_session_coords(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected resolve_session_coords to error"),
        };
        assert!(e.contains("no local master session"), "got: {e}");
        assert!(
            !e.contains("not registered on chain"),
            "must drop the old misleading wording: {e}"
        );
        // Persisted-but-expired coords (master_session present, no live session) ⇒
        // "expired — re-authenticate", NOT "device not registered on chain".
        *state.master_session.write().await =
            Some(persisted_record(&format!("0x{}", "11".repeat(32)), 1));
        let e = match resolve_session_coords(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected resolve_session_coords to error"),
        };
        assert!(e.contains("expired") && e.contains("re-auth"), "got: {e}");
        assert!(!e.contains("not registered on chain"), "got: {e}");
    }

    #[tokio::test]
    async fn onboarding_state_reports_session_signal() {
        let state = make_state();
        // none initially.
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.session,
            "none"
        );
        // Persisted but no live session ⇒ "expired" (drives one passkey re-auth).
        *state.master_session.write().await =
            Some(persisted_record(&format!("0x{}", "22".repeat(32)), 1));
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.session,
            "expired"
        );
        // A live session with a non-empty J1 ⇒ "active".
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "m@x".into(),
            omni: format!("0x{}", "22".repeat(32)),
            j1: "eyJ.live.jwt".into(),
            wallet: "0xW".into(),
        });
        assert_eq!(onboarding_state(State(state)).await.0.session, "active");
    }

    #[tokio::test]
    async fn rehydrate_restores_valid_session_with_zero_prompts() {
        // A persisted record with a still-valid J1 → onboarding_session +
        // registered_master repopulate → identity verified, session active, chain
        // master-registered: the web pages work with ZERO prompts after a restart.
        let tmp = tempfile::tempdir().unwrap();
        let store = MasterSessionStore::new(tmp.path().join(".agentkeys"));
        let omni = format!("0x{}", "33".repeat(32));
        let far_future = master_session::now_unix() + 10_000;
        store
            .save(&persisted_record(&omni, far_future))
            .expect("save");

        let state = make_state_real(Some(store));
        rehydrate_master_session(&state).await;

        let os = onboarding_state(State(state.clone())).await.0;
        assert_eq!(os.identity, "verified");
        assert_eq!(os.session, "active");
        assert_eq!(os.chain, "master-registered");
        let dkh = agentkeys_core::device_crypto::device_key_hash_from_omni(&omni).unwrap();
        assert_eq!(
            state
                .registered_master
                .read()
                .await
                .as_ref()
                .unwrap()
                .device_key_hash,
            dkh
        );
        // And cap-mint coordinates resolve cleanly (no --master-device-key-hash).
        let coords = resolve_session_coords(&state).await.expect("coords");
        assert_eq!(coords.device_key_hash, dkh);
    }

    #[tokio::test]
    async fn rehydrate_expired_session_loads_coords_but_not_live() {
        // An expired J1 → coords load into master_session (so session: "expired")
        // but onboarding_session stays empty (the dead J1 isn't usable). Exactly
        // one passkey re-auth restores it — not a full re-onboarding.
        let tmp = tempfile::tempdir().unwrap();
        let store = MasterSessionStore::new(tmp.path().join(".agentkeys"));
        let omni = format!("0x{}", "44".repeat(32));
        let past = master_session::now_unix().saturating_sub(10);
        store.save(&persisted_record(&omni, past)).expect("save");

        let state = make_state_real(Some(store));
        rehydrate_master_session(&state).await;

        assert!(state.onboarding_session.read().await.is_none());
        assert!(state.master_session.read().await.is_some());
        let os = onboarding_state(State(state.clone())).await.0;
        assert_eq!(os.identity, "none");
        assert_eq!(os.session, "expired");
        // resolve fails with the re-auth message, never the misleading old one.
        let e = match resolve_session_coords(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected resolve_session_coords to error"),
        };
        assert!(e.contains("expired"), "got: {e}");
    }

    // ─── issue #242: logout keeps identity; passkey re-login restores it ─────

    #[tokio::test]
    async fn logout_downgrades_to_expired_and_offers_relogin() {
        // Login (rehydrated valid session) → logout: the live session + J1 are
        // GONE, but the identity coords survive as an EXPIRED record — the state
        // reports session: "expired" + the relogin hint, and a restart can never
        // silently rehydrate the logged-out session (#220 guarantee preserved).
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join(".agentkeys");
        let omni = format!("0x{}", "55".repeat(32));
        let far_future = master_session::now_unix() + 10_000;
        let store = MasterSessionStore::new(base.clone());
        store
            .save(&persisted_record(&omni, far_future))
            .expect("save");
        let state = make_state_real(Some(store));
        rehydrate_master_session(&state).await;
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.session,
            "active"
        );

        let _ = logout(State(state.clone())).await;

        assert!(state.onboarding_session.read().await.is_none());
        let held = state.master_session.read().await.clone().expect("coords");
        assert!(held.j1.is_empty(), "logout must drop the J1");
        let os = onboarding_state(State(state.clone())).await.0;
        assert_eq!(os.identity, "none");
        assert_eq!(os.session, "expired");
        let relogin = os.relogin.expect("relogin hint after logout");
        assert_eq!(relogin.omni, omni);
        assert_eq!(relogin.email.as_deref(), Some("master@example.com"));

        // A fresh daemon over the same store: coords-only, never a live session.
        let state2 = make_state_real(Some(MasterSessionStore::new(base)));
        rehydrate_master_session(&state2).await;
        assert!(state2.onboarding_session.read().await.is_none());
        assert_eq!(onboarding_state(State(state2)).await.0.session, "expired");
    }

    #[tokio::test]
    async fn onboarding_state_chain_is_keyed_on_the_live_session_omni() {
        // #242 cross-email guard: a held binding for omni A must NOT be reported
        // as "master-registered" to a live session for omni B (the new-email
        // onboarding would skip the enroll + reuse the WRONG passkey pointer).
        let state = make_state();
        let omni_a = format!("0x{}", "0a".repeat(32));
        let omni_b = format!("0x{}", "0b".repeat(32));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: "0xdkh".into(),
            operator_omni: omni_a.clone(),
            tx_hash: None,
            account: None,
        });

        // No live session: the held binding is reported as-is.
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.chain,
            "master-registered"
        );
        // Live session for the SAME omni: registered.
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "a@x".into(),
            omni: omni_a.clone(),
            j1: "eyJ.j1".into(),
            wallet: "0xA".into(),
        });
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.chain,
            "master-registered"
        );
        // Live session for a DIFFERENT omni: the old binding must not leak in.
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "b@x".into(),
            omni: omni_b,
            j1: "eyJ.j1".into(),
            wallet: "0xB".into(),
        });
        assert_eq!(onboarding_state(State(state.clone())).await.0.chain, "none");
    }

    #[tokio::test]
    async fn relogin_requires_held_identity() {
        // No coords (fresh machine / after master reset) → CONFLICT with the
        // onboard-first reason; the email path is the only way in.
        let state = make_state_real(None);
        let e = relogin_start(State(state), HeaderMap::new())
            .await
            .expect_err("expected relogin_start to fail");
        assert_eq!(e.0, StatusCode::CONFLICT);
        assert_eq!(e.1 .0.reason, "no-master-identity");
    }

    #[tokio::test]
    async fn relogin_finish_restores_the_session_from_a_verified_assertion() {
        // Stub broker: verify succeeds for the held omni → the daemon restores
        // onboarding_session (fresh J1) + registered_master + re-persists. ONE
        // passkey prompt, zero emails, working session.
        let omni = format!("0x{}", "66".repeat(32));
        let omni_resp = omni.clone();
        let app = Router::new().route(
            "/v1/auth/passkey/verify",
            post(move |Json(body): Json<serde_json::Value>| {
                let omni = omni_resp.clone();
                async move {
                    assert!(body.get("challenge").is_some());
                    assert!(body.get("assertion").is_some());
                    Json(serde_json::json!({
                        "status": "verified",
                        "session_jwt": "eyJ.fresh.relogin.jwt",
                        "omni_account": omni,
                    }))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let tmp = tempfile::tempdir().unwrap();
        let store = MasterSessionStore::new(tmp.path().join(".agentkeys"));
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some(format!("http://{addr}")),
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            None,
            Some(store),
        )
        .unwrap();
        // Logged-out coords (expired record) — what the login screen sees.
        let mut record = persisted_record(&omni, 0);
        record.j1 = String::new();
        *state.master_session.write().await = Some(record);

        let resp = relogin_finish(
            State(state.clone()),
            HeaderMap::new(),
            Json(ReloginFinishRequest {
                challenge: format!("0x{}", "77".repeat(32)),
                assertion: serde_json::json!({
                    "authenticator_data": "AA",
                    "client_data_json": "e30",
                    "signature": "AA",
                    "credential_id": "AA",
                }),
            }),
        )
        .await
        .expect("relogin_finish ok");
        assert_eq!(resp.0.get("ok"), Some(&serde_json::Value::Bool(true)));

        let session = state
            .onboarding_session
            .read()
            .await
            .clone()
            .expect("live session restored");
        assert_eq!(session.j1, "eyJ.fresh.relogin.jwt");
        assert_eq!(session.omni, omni);
        assert_eq!(session.email, "master@example.com");
        assert_eq!(session.wallet, "0xMASTERWALLET");
        assert_eq!(
            state
                .registered_master
                .read()
                .await
                .as_ref()
                .expect("registered_master restored")
                .operator_omni,
            omni
        );
        let os = onboarding_state(State(state)).await.0;
        assert_eq!(os.identity, "verified");
        assert_eq!(os.session, "active");
        assert_eq!(os.chain, "master-registered");
    }

    fn cat(ns: &str, label: &str) -> MemoryCategory {
        MemoryCategory {
            ns: ns.into(),
            label: label.into(),
        }
    }

    // ─── #207 item 1A: authored-taxonomy bootstrap ──────────────────────────

    #[test]
    fn merge_categories_preserves_existing_and_adds_new() {
        // Existing labels win (an authored label / user edit is never clobbered);
        // a new ns is appended; output is ns-sorted for a stable blob.
        let existing = vec![cat("travel", "Travel"), cat("finance", "Finance")];
        let incoming = vec![
            cat("finance", "Finance & Investment"), // same ns → existing label kept
            cat("kids", "Kids"),                    // new ns → added
        ];
        let merged = merge_categories(existing, &incoming);
        let by_ns: std::collections::BTreeMap<_, _> = merged
            .iter()
            .map(|c| (c.ns.as_str(), c.label.as_str()))
            .collect();
        assert_eq!(by_ns.get("finance"), Some(&"Finance")); // existing wins
        assert_eq!(by_ns.get("kids"), Some(&"Kids"));
        assert_eq!(merged.len(), 3);
        // ns-sorted
        let ns: Vec<&str> = merged.iter().map(|c| c.ns.as_str()).collect();
        assert_eq!(ns, ["finance", "kids", "travel"]);
    }

    #[tokio::test]
    async fn init_default_authors_taxonomy_not_plant_derived() {
        // Acceptance (#207): the DEFAULT preset writes a REAL authored taxonomy
        // even with ZERO memory planted — the old path could only derive
        // categories from planted namespaces.
        let state = make_state();
        let resp = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init default");
        assert_eq!(resp.preset_id, crate::presets::DEFAULT_PRESET_ID);
        assert_eq!(resp.taxonomy_status, "cached"); // Config unconfigured in tests
        let ns: Vec<&str> = resp.categories.iter().map(|c| c.ns.as_str()).collect();
        for required in ["kids", "business", "smart-home", "finance", "family"] {
            assert!(
                ns.contains(&required),
                "authored taxonomy missing {required}"
            );
        }
        // And the master-memory list now resolves those authored categories with
        // NOTHING planted (proves "authored, not plant-derived").
        let listed = resolve_categories(&state).await.expect("resolve");
        assert_eq!(listed.len(), resp.categories.len());
    }

    #[tokio::test]
    async fn init_then_plant_preserves_authored_categories() {
        // Author a preset, then simulate a plant (a memory entry in the cache).
        // The list must be authored ∪ planted — the plant adds its namespace but
        // never drops an authored one (merge-not-clobber).
        let state = make_state();
        init_config_default_inner(
            &state,
            &InitConfigRequest {
                preset_id: "investor".into(),
            },
        )
        .await
        .expect("init investor");

        state.master_memory.write().await.insert(
            "h1".into(),
            ApiMemoryEntry {
                ns: "travel".into(),
                key: "chengdu".into(),
                title: "Chengdu".into(),
                bytes: 4,
                version: "v1".into(),
                updated: "2026-06-06".into(),
                preview: "trip".into(),
                body: "trip".into(),
                content_hash: "h1".into(),
                kind: ContextKind::Knowledge,
            },
        );

        let listed = resolve_categories(&state).await.expect("resolve");
        let ns: std::collections::BTreeSet<&str> = listed.iter().map(|c| c.ns.as_str()).collect();
        // authored investor namespaces survive…
        assert!(ns.contains("investment") && ns.contains("markets"));
        // …and the planted namespace is added.
        assert!(ns.contains("travel"));
    }

    #[tokio::test]
    async fn init_is_idempotent() {
        let state = make_state();
        let first = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init 1")
            .categories
            .len();
        let second = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init 2")
            .categories
            .len();
        assert_eq!(first, second, "re-init must not grow the taxonomy");
    }

    #[tokio::test]
    async fn init_preserves_a_pre_existing_planted_namespace() {
        // Idempotency invariant (#207): init MERGES into the existing taxonomy —
        // it must NEVER clobber/delete a namespace a prior plant added. Seed a
        // "planted" namespace not in any preset, then init the default; the
        // planted namespace must survive alongside the newly-authored ones.
        let state = make_state();
        *state.authored_taxonomy.write().await = Some(MemoryTaxonomy {
            version: 1,
            categories: vec![cat("chengdu-trip", "Chengdu Trip")],
        });
        let resp = init_config_default_inner(&state, &InitConfigRequest::default())
            .await
            .expect("init");
        let ns: Vec<&str> = resp.categories.iter().map(|c| c.ns.as_str()).collect();
        assert!(
            ns.contains(&"chengdu-trip"),
            "init DELETED the planted namespace — not idempotent/non-destructive"
        );
        assert!(
            ns.contains(&"kids"),
            "init did not add the preset categories"
        );
    }

    #[tokio::test]
    async fn init_unknown_preset_is_bad_request() {
        let state = make_state();
        let err = init_config_default_inner(
            &state,
            &InitConfigRequest {
                preset_id: "nope".into(),
            },
        )
        .await
        .expect_err("unknown preset must 400");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    // ─── #207 items 5 + 7: classify bridge + auto-distribute gating ─────────

    #[tokio::test]
    async fn classify_entity_local_categorizes_known_service() {
        // No --classify-url ⇒ local catalog tier-0. A known service resolves to
        // its category + the catalog floor sensitivity (cred auto-categorize, #207 7).
        let state = make_state();
        let stripe = classify_entity(&state, "credentials", "Stripe").await;
        assert_eq!(stripe.category, "payments");
        assert_eq!(
            stripe.sensitivity,
            agentkeys_catalog::Sensitivity::Sensitive
        );
        let notion = classify_entity(&state, "credentials", "notion").await;
        assert_eq!(notion.category, "productivity");
        assert_eq!(notion.sensitivity, agentkeys_catalog::Sensitivity::Safe);
    }

    #[tokio::test]
    async fn classify_entity_local_unknown_is_deny_by_default() {
        let state = make_state();
        let u = classify_entity(&state, "credentials", "totally-unknown-xyz").await;
        assert_eq!(u.category, "unknown");
        assert_eq!(u.sensitivity, agentkeys_catalog::Sensitivity::Sensitive);
    }

    #[test]
    fn gating_tiers_safe_auto_sensitive_k11() {
        // #207 §3 invariant 2: Safe → auto (auto-confirm + daily review),
        // Sensitive → k11 (explicit per-grant confirm). The tier is the CATALOG's.
        assert_eq!(
            gating_for(agentkeys_catalog::Sensitivity::Safe),
            ScopeGating::Auto
        );
        assert_eq!(
            gating_for(agentkeys_catalog::Sensitivity::Sensitive),
            ScopeGating::K11
        );
        // The wire spellings are pinned: a rename breaks the generated TS union.
        assert_eq!(
            serde_json::to_value(ScopeGating::Auto).unwrap(),
            serde_json::json!("auto")
        );
        assert_eq!(
            serde_json::to_value(ScopeGating::K11).unwrap(),
            serde_json::json!("k11")
        );
    }

    #[tokio::test]
    async fn auto_distribute_sensitive_service_is_k11_gated() {
        // The load-bearing invariant surfaced: a sensitive cred (stripe→payments)
        // proposes as k11 (NOT auto) — it can never be silently granted; only the
        // explicit K11 confirm path writes scope. A safe one (notion) is auto.
        let state = make_state();
        let stripe = classify_entity(&state, "credentials", "stripe").await;
        assert_eq!(gating_for(stripe.sensitivity), ScopeGating::K11);
        let notion = classify_entity(&state, "credentials", "notion").await;
        assert_eq!(gating_for(notion.sensitivity), ScopeGating::Auto);
    }

    #[test]
    fn service_for_builds_memory_and_cred_services() {
        assert_eq!(service_for("memory", "Travel"), "memory:travel");
        assert_eq!(service_for("credentials", "OpenRouter"), "openrouter");
    }

    #[tokio::test]
    async fn memory_namespace_inheritance_uses_category_floor() {
        // #207 item 8 — a memory namespace is classified as its CATEGORY (floor),
        // not a service lookup: travel → Safe (auto), health/finance → Sensitive
        // (explicit pick). A namespace the catalog doesn't vouch for → Sensitive.
        let state = make_state();
        let travel = classify_entity(&state, "memory", "travel").await;
        assert_eq!(travel.category, "travel");
        assert_eq!(gating_for(travel.sensitivity), ScopeGating::Auto);
        let health = classify_entity(&state, "memory", "health").await;
        assert_eq!(gating_for(health.sensitivity), ScopeGating::K11);
        let finance = classify_entity(&state, "memory", "finance").await;
        assert_eq!(gating_for(finance.sensitivity), ScopeGating::K11);
        // unknown namespace → conservative Sensitive (explicit pick).
        let kids = classify_entity(&state, "memory", "kids").await;
        assert_eq!(gating_for(kids.sensitivity), ScopeGating::K11);
    }

    #[tokio::test]
    async fn list_credentials_empty_when_cred_worker_unconfigured() {
        // Credentials are the same abstraction as memory, with the same honesty:
        // no cred worker configured (AGENTKEYS_WORKER_CRED_URL unset in `cargo test`)
        // → empty (real-data-or-nothing, no in-memory stand-in). A configured-but-
        // broken worker would 502 instead (real_cred_ctx Ok(Some) → worker error).
        if std::env::var("AGENTKEYS_WORKER_CRED_URL")
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            return; // runner has a cred worker configured — skip the unconfigured assertion
        }
        let state = make_state();
        let creds = list_master_credentials_inner(&state).await.expect("list");
        assert!(creds.is_empty());
    }

    #[test]
    fn normalize_data_class_defaults_and_validates() {
        assert_eq!(normalize_data_class("").unwrap(), "credentials");
        assert_eq!(normalize_data_class("Memory").unwrap(), "memory");
        assert!(normalize_data_class("payments").is_err());
    }

    #[tokio::test]
    async fn real_memory_ctx_none_when_unconfigured() {
        // No --memory-url ⇒ in-memory fallback (Ok(None)), not an error.
        let state = make_state();
        assert!(real_memory_ctx(&state).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn real_memory_ctx_errs_on_partial_config() {
        // --memory-url set but MEMORY_ROLE_ARN missing ⇒ fail loud (issue #90),
        // never a silent per-actor-isolation downgrade.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("https://broker.example".into()),
            None,
            84532,
            Some("https://memory.example".into()),
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            Some("0xdkh".into()),
            None,
            None, // #220 master_session_store
        )
        .unwrap();
        let err = match real_memory_ctx(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected real_memory_ctx to return Err"),
        };
        assert!(err.contains("MEMORY_ROLE_ARN"), "got: {err}");
    }

    #[tokio::test]
    async fn real_memory_ctx_errs_when_not_logged_in() {
        // Fully configured but no onboarding session ⇒ Err (onboard first),
        // not a silent no-op.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some("https://broker.example".into()),
            None,
            84532,
            Some("https://memory.example".into()),
            Some("arn:aws:iam::1:role/memory".into()),
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            Some("0xdkh".into()),
            None,
            None, // #220 master_session_store
        )
        .unwrap();
        let err = match real_memory_ctx(&state).await {
            Err(e) => e,
            Ok(_) => panic!("expected real_memory_ctx to return Err"),
        };
        assert!(err.contains("session"), "got: {err}");
    }

    #[tokio::test]
    async fn auth_email_start_without_broker_is_unavailable() {
        // make_state() builds with broker_url = None ⇒ email onboarding is
        // disabled, so the endpoint fails closed (503 broker-not-configured)
        // rather than silently no-op'ing.
        let state = make_state();
        let e = auth_email_start(
            State(state),
            axum::http::HeaderMap::new(),
            Json(EmailStartRequest {
                email: "sara@example.com".into(),
            }),
        )
        .await
        .expect_err("no broker configured should error");
        assert_eq!(e.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.1 .0.reason, "broker-not-configured");
    }

    #[tokio::test]
    async fn auth_email_start_rejects_cross_origin() {
        // make_state()'s allowed origin is http://localhost:3113; a request
        // carrying a different Origin is rejected before any broker call —
        // the server-side gate on top of CORS.
        let state = make_state();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("origin", "http://evil.example".parse().unwrap());
        let e = auth_email_start(
            State(state),
            headers,
            Json(EmailStartRequest {
                email: "sara@example.com".into(),
            }),
        )
        .await
        .expect_err("cross-origin should be rejected");
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert_eq!(e.1 .0.reason, "bad-origin");
    }

    #[tokio::test]
    async fn onboarding_state_reflects_session_and_logout() {
        let state = make_state();
        // No session held yet → identity "none".
        assert_eq!(
            onboarding_state(State(state.clone())).await.0.identity,
            "none"
        );
        // Simulate a verified magic-link click.
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "sara@example.com".into(),
            omni: "0xabc123".into(),
            j1: String::new(),
            wallet: String::new(),
        });
        let s = onboarding_state(State(state.clone())).await;
        assert_eq!(s.0.identity, "verified");
        assert_eq!(s.0.email.as_deref(), Some("sara@example.com"));
        assert_eq!(s.0.omni.as_deref(), Some("0xabc123"));
        // Logout clears it → re-testable.
        let _ = logout(State(state.clone())).await;
        assert_eq!(onboarding_state(State(state)).await.0.identity, "none");
    }

    #[tokio::test]
    async fn begin_returns_user_id_and_creation_options() {
        let state = make_state();
        let resp = enroll_begin(
            State(state.clone()),
            Json(EnrollBeginRequest {
                username: "sara@example.com".into(),
                display_name: "Sara".into(),
            }),
        )
        .await
        .expect("begin should succeed");
        assert!(!resp.0.user_id.is_empty(), "user_id must be set");
        assert!(
            resp.0.creation_options.get("publicKey").is_some(),
            "creation_options must contain publicKey field per WebAuthn spec, got: {}",
            resp.0.creation_options
        );

        let guard = state.enroll.read().await;
        assert!(
            guard.pending.contains_key(&resp.0.user_id),
            "pending registration must be stored"
        );
    }

    #[tokio::test]
    async fn begin_rejects_empty_username() {
        let state = make_state();
        let err = enroll_begin(
            State(state),
            Json(EnrollBeginRequest {
                username: "   ".into(),
                display_name: "Sara".into(),
            }),
        )
        .await
        .expect_err("empty username must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "missing-username");
    }

    #[tokio::test]
    async fn finish_with_unknown_user_id_returns_no_pending() {
        let state = make_state();
        let err = enroll_finish(
            State(state),
            Json(EnrollFinishRequest {
                user_id: "00000000-0000-0000-0000-000000000000".into(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjGSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAALraVWanqkAfvZZFYZpVEg0AQg",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("unknown user_id must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "no-pending");
    }

    #[tokio::test]
    async fn finish_with_malformed_credential_returns_malformed() {
        let state = make_state();
        let err = enroll_finish(
            State(state),
            Json(EnrollFinishRequest {
                user_id: "doesn-t-matter".into(),
                credential: serde_json::json!({ "totally": "not a credential" }),
            }),
        )
        .await
        .expect_err("malformed credential must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1 .0.reason, "credential-malformed");
    }

    #[tokio::test]
    async fn replay_after_consume_returns_no_pending() {
        // First begin to get a real user_id, then finish twice with the
        // SAME user_id and the same (malformed-but-parseable-only-the-second-time)
        // credential — we don't need a real attestation for this assertion,
        // we just need to confirm the pending entry is consumed on first
        // attempt regardless of finish outcome.
        let state = make_state();
        let begin_resp = enroll_begin(
            State(state.clone()),
            Json(EnrollBeginRequest {
                username: "replay@example.com".into(),
                display_name: "Replay Test".into(),
            }),
        )
        .await
        .unwrap();
        let user_id = begin_resp.0.user_id;

        // Confirm pending exists.
        assert!(state.enroll.read().await.pending.contains_key(&user_id));

        // First finish (with malformed credential — fails before pending consume).
        let _ = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({ "not": "valid" }),
            }),
        )
        .await
        .expect_err("first finish should fail at parse");

        // Pending should STILL exist because parse failed before consume.
        assert!(
            state.enroll.read().await.pending.contains_key(&user_id),
            "pending must survive a parse-stage failure so the user can retry"
        );

        // Now simulate a valid-shaped-but-bad-attestation credential. Pending
        // gets consumed on .remove() call, and webauthn-rs rejects the
        // attestation.
        let _ = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZQ",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("second finish must fail attestation");

        // Pending must NOT exist anymore — consume happened at .remove().
        assert!(
            !state.enroll.read().await.pending.contains_key(&user_id),
            "pending must be consumed after a finish attempt that parsed the credential"
        );

        // Third finish should fail with no-pending.
        let err = enroll_finish(
            State(state.clone()),
            Json(EnrollFinishRequest {
                user_id: user_id.clone(),
                credential: serde_json::json!({
                    "id": "test",
                    "rawId": "dGVzdA",
                    "response": {
                        "attestationObject": "o2NmbXRkbm9uZQ",
                        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
                    },
                    "type": "public-key"
                }),
            }),
        )
        .await
        .expect_err("third finish must fail no-pending after consume");
        assert_eq!(err.1 .0.reason, "no-pending");
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let resp = healthz().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn seed_actor(state: &SharedUiBridgeState) -> ApiActor {
        let actor = ApiActor {
            id: "agent-folotoy".into(),
            omni: "O_master//folotoy".into(),
            omni_hex: "0x7c2d…41a9".into(),
            label: "FoloToy bear".into(),
            role: "agent".into(),
            parent: Some("master".into()),
            derivation: "//folotoy".into(),
            device: "FoloToy hardware".into(),
            device_pubkey: "D_pub_folotoy".into(),
            last_active: "now".into(),
            status: "ok".into(),
            vendor: "FoloToy Inc.".into(),
            k11: false,
            device_key_hash: None,
            scope: None,
            scope_unknown_service_ids: None,
            payment_cap: None,
            time_window: None,
            services: None,
            account_address: None,
            account_type: None,
            preset_id: None,
            memory_ns: None,
        };
        let cloned = actor.clone();
        let st = state.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { st.actors.write().await.insert(cloned.id.clone(), cloned) })
        });
        actor
    }

    async fn seed_actor_async(state: &SharedUiBridgeState) -> ApiActor {
        let actor = ApiActor {
            id: "agent-folotoy".into(),
            omni: "O_master//folotoy".into(),
            omni_hex: "0x7c2d…41a9".into(),
            label: "FoloToy bear".into(),
            role: "agent".into(),
            parent: Some("master".into()),
            derivation: "//folotoy".into(),
            device: "FoloToy hardware".into(),
            device_pubkey: "D_pub_folotoy".into(),
            last_active: "now".into(),
            status: "ok".into(),
            vendor: "FoloToy Inc.".into(),
            k11: false,
            device_key_hash: None,
            scope: None,
            scope_unknown_service_ids: None,
            payment_cap: None,
            time_window: None,
            services: None,
            account_address: None,
            account_type: None,
            preset_id: None,
            memory_ns: None,
        };
        state
            .actors
            .write()
            .await
            .insert(actor.id.clone(), actor.clone());
        actor
    }

    #[tokio::test]
    async fn list_actors_returns_empty_when_nothing_registered() {
        let state = make_state();
        let resp = list_actors(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn list_actors_returns_master_first() {
        let state = make_state();
        let mut actors = state.actors.write().await;
        actors.insert(
            "agent-1".into(),
            ApiActor {
                id: "agent-1".into(),
                role: "agent".into(),
                omni: "x".into(),
                omni_hex: "x".into(),
                label: "agent-1".into(),
                parent: Some("master".into()),
                derivation: "//agent1".into(),
                device: "".into(),
                device_pubkey: "".into(),
                last_active: "now".into(),
                status: "ok".into(),
                vendor: "".into(),
                k11: false,
                device_key_hash: None,
                scope: None,
                scope_unknown_service_ids: None,
                payment_cap: None,
                time_window: None,
                services: None,
                account_address: None,
                account_type: None,
                preset_id: None,
                memory_ns: None,
            },
        );
        actors.insert(
            "master".into(),
            ApiActor {
                id: "master".into(),
                role: "master".into(),
                omni: "O_master".into(),
                omni_hex: "x".into(),
                label: "Sara".into(),
                parent: None,
                derivation: "/".into(),
                device: "".into(),
                device_pubkey: "".into(),
                last_active: "now".into(),
                status: "ok".into(),
                vendor: "self".into(),
                k11: true,
                device_key_hash: None,
                scope: None,
                scope_unknown_service_ids: None,
                payment_cap: None,
                time_window: None,
                services: None,
                account_address: None,
                account_type: None,
                preset_id: None,
                memory_ns: None,
            },
        );
        drop(actors);

        // Decode the JSON to check ordering invariant.
        let resp = list_actors(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actors_arr = json["actors"].as_array().unwrap();
        assert_eq!(actors_arr[0]["role"], "master", "master must come first");
    }

    #[tokio::test]
    async fn get_actor_unknown_returns_404() {
        let state = make_state();
        let err = get_actor(State(state), Path("does-not-exist".into()))
            .await
            .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.reason, "actor-not-found");
    }

    #[tokio::test]
    async fn get_actor_known_returns_payload() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = get_actor(State(state), Path("agent-folotoy".into()))
            .await
            .unwrap();
        assert_eq!(resp.0["label"], "FoloToy bear");
        // E7 actor-page: an agent surfaces its device identity (not a P256Account).
        assert_eq!(resp.0["account_type"], "device");
    }

    #[tokio::test]
    async fn update_scope_writes_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = update_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(UpdateScopeRequest {
                namespace: "family".into(),
                read: true,
                write: false,
            }),
        )
        .await
        .unwrap();
        assert!(resp.0.scope.as_ref().unwrap().get("family").unwrap().read);
        // Audit event landed.
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "scope.updated"));
    }

    #[tokio::test]
    async fn update_scope_unknown_actor_404() {
        let state = make_state();
        let err = update_scope(
            State(state),
            Path("nope".into()),
            Json(UpdateScopeRequest {
                namespace: "family".into(),
                read: true,
                write: false,
            }),
        )
        .await
        .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn grant_service_scope_records_cred_and_memory() {
        // #207 items 7/8 — a CONFIRMED grant persists in actor state + audits.
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = grant_service_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(GrantScopeRequest {
                data_class: "credentials".into(),
                entity: "openrouter".into(),
                category: "ai-services".into(),
                gating: "auto".into(),
            }),
        )
        .await
        .unwrap();
        assert!(resp
            .0
            .services
            .as_ref()
            .unwrap()
            .contains(&"openrouter".to_string()));

        let resp2 = grant_service_scope(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(GrantScopeRequest {
                data_class: "memory".into(),
                entity: "travel".into(),
                category: "travel".into(),
                gating: "k11".into(),
            }),
        )
        .await
        .unwrap();
        assert!(resp2.0.scope.as_ref().unwrap().get("travel").unwrap().read);
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "scope.granted"));
    }

    #[tokio::test]
    async fn grant_service_scope_unknown_actor_404() {
        let state = make_state();
        let err = grant_service_scope(
            State(state),
            Path("nope".into()),
            Json(GrantScopeRequest {
                data_class: "credentials".into(),
                entity: "x".into(),
                category: String::new(),
                gating: String::new(),
            }),
        )
        .await
        .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_payment_cap_writes_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        let resp = update_payment_cap(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(UpdatePaymentCapRequest {
                per_tx: 5.0,
                daily: 25.0,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.payment_cap.as_ref().unwrap().per_tx, 5.0);
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "payment-cap.updated"));
    }

    #[tokio::test]
    async fn revoke_device_flips_status_and_clears_caps() {
        // revoke_device now goes ON CHAIN (heima-device-revoke.sh, resolved as a
        // sibling of register_master_script). Point at a tempdir with a fake script
        // that exits 0 so the test exercises the on-chain-then-local-flip path.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            "#!/usr/bin/env bash\necho '{\"ok\":true,\"skipped\":\"already-revoked\"}'\n",
        )
        .unwrap();
        let state =
            make_state_with_script(tmp.path().join("master.sh").to_string_lossy().into_owned());
        seed_actor_async(&state).await;
        // Pre-seed some caps so we can verify they're cleared.
        state.caps.write().await.insert(
            "agent-folotoy".into(),
            vec![ApiCapToken {
                id: "cap-1".into(),
                cap: "memory:read".into(),
                scope: "family".into(),
                ttl: "900s".into(),
                minted: "now".into(),
                danger: None,
            }],
        );

        let resp = revoke_device(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeDeviceRequest {
                intent_text: "Revoke FoloToy".into(),
                intent_fields: vec![("actor".into(), "agent-folotoy".into())],
                onchain: false,
                onchain_tx_hash: None,
                audit_envelope_hashes: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.status, "bad");
        assert!(resp.0.label.ends_with("(revoked)"));
        assert!(state.caps.read().await.get("agent-folotoy").is_none());
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "device.revoked"));
    }

    #[tokio::test]
    async fn revoke_device_prefers_the_onchain_hash_over_the_label_file() {
        // Chain-reconstructed actors (#233) have NO ~/.agentkeys/agents/<label>.json,
        // so the label path dies with "no agent file" (real 2026-06-11 unpair
        // incident). When device_key_hash is known, the revoke must shell
        // `--device-key-hash <hash>` — never `--agent <label>`.
        let tmp = tempfile::tempdir().unwrap();
        let args_file = tmp.path().join("revoke-args.txt");
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            format!(
                "#!/usr/bin/env bash\necho \"$@\" > {}\necho '{{\"ok\":true,\"tx_hash\":\"0xrevoketx\"}}'\n",
                args_file.display()
            ),
        )
        .unwrap();
        let state =
            make_state_with_script(tmp.path().join("master.sh").to_string_lossy().into_owned());
        seed_actor_async(&state).await;
        let hash = format!("0x{}", "ab".repeat(32));
        state
            .actors
            .write()
            .await
            .get_mut("agent-folotoy")
            .unwrap()
            .device_key_hash = Some(hash.clone());

        let resp = revoke_device(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeDeviceRequest {
                intent_text: "Revoke FoloToy".into(),
                intent_fields: vec![],
                onchain: false,
                onchain_tx_hash: None,
                audit_envelope_hashes: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.status, "bad");

        let recorded = std::fs::read_to_string(&args_file).unwrap();
        assert!(
            recorded.contains("--device-key-hash") && recorded.contains(&hash),
            "expected by-hash revoke, got: {recorded}"
        );
        assert!(!recorded.contains("--agent"), "got: {recorded}");
    }

    #[tokio::test]
    async fn revoke_device_onchain_mode_verifies_the_registry_and_skips_the_script() {
        // The Touch-ID unpair: the browser already landed the revoke UserOp
        // (/v1/revoke/{build,submit}); the daemon must VERIFY the device reads
        // `revoked` from SidecarRegistry (never trust the client), flip local
        // state WITHOUT shelling heima-device-revoke.sh, and 409 when the chain
        // still says active.
        let addr = spawn_chain_stub().await;
        let mut state = make_state_real(None);
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        seed_actor_async(&state).await;
        // The stub's getDevice: unknown hashes → a REVOKED agent entry.
        state
            .actors
            .write()
            .await
            .get_mut("agent-folotoy")
            .unwrap()
            .device_key_hash = Some(format!("0x{}", T233_REVOKED_HASH.repeat(32)));

        let resp = revoke_device(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeDeviceRequest {
                intent_text: "Unpair".into(),
                intent_fields: vec![],
                onchain: true,
                onchain_tx_hash: Some("0xdeadbeef".into()),
                audit_envelope_hashes: None,
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0.status, "bad");
        assert!(state
            .audit
            .read()
            .await
            .iter()
            .any(|e| e.kind == "device.revoked" && e.detail.contains("0xdeadbeef")));

        // ACTIVE on chain (the stub's 0x22… agent) → refuse to flip local state.
        state
            .actors
            .write()
            .await
            .get_mut("agent-folotoy")
            .unwrap()
            .device_key_hash = Some(format!("0x{}", T233_AGENT_HASH.repeat(32)));
        let denied = revoke_device(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeDeviceRequest {
                intent_text: "Unpair".into(),
                intent_fields: vec![],
                onchain: true,
                onchain_tx_hash: None,
                audit_envelope_hashes: None,
            }),
        )
        .await;
        let (status, _) = denied.expect_err("active device must be refused");
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // ─── issue #243: master reset tears down the whole fleet ────────────────

    /// Stub JSON-RPC chain holding an EMPTY fleet: `getOperatorDevices` → `[]`,
    /// everything else (`operatorMasterWallet`, `getScope`) → one zero word.
    /// Keeps the #233 reconciliation inside `master_reset` deterministic and
    /// offline — without it the test eth_calls whatever RPC the built-in
    /// profile names.
    async fn spawn_empty_chain_stub() -> std::net::SocketAddr {
        let app = Router::new().route(
            "/",
            post(|Json(body): Json<serde_json::Value>| async move {
                let data = body["params"][0]["data"].as_str().unwrap_or("");
                let sel_devices = chain_selector("getOperatorDevices(bytes32)");
                let result = if data.starts_with(&format!("0x{sel_devices}")) {
                    format!("0x{:0>64x}{:0>64x}", 0x20, 0) // offset, len = 0
                } else {
                    format!("0x{:0>64x}", 0)
                };
                Json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn master_reset_tears_down_the_fleet() {
        // Reset must leave NOTHING attached: pending pairings declined at the
        // broker, paired agents revoked on chain (+ audit row each), actors/caps
        // cleared, and the K11 enroll store emptied (k11: "none", chain: "none").
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            "#!/usr/bin/env bash\necho '{\"ok\":true,\"tx_hash\":\"0xrevoketx\"}'\n",
        )
        .unwrap();

        // Stub broker: two pending rows; every decline succeeds.
        let app = Router::new()
            .route(
                "/v1/agent/pending-bindings",
                axum::routing::get(|| async {
                    Json(serde_json::json!({
                        "pending": [ { "request_id": "req-1" }, { "request_id": "req-2" } ]
                    }))
                }),
            )
            .route(
                "/v1/agent/pairing/decline",
                post(|Json(b): Json<serde_json::Value>| async move {
                    assert!(b.get("request_id").is_some());
                    Json(serde_json::json!({ "ok": true }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let chain = spawn_empty_chain_stub().await;

        let mut state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some(format!("http://{addr}")),
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(tmp.path().join("master.sh").to_string_lossy().into_owned()),
            None,
        )
        .unwrap();
        set_chain_rpc(&mut state, &format!("http://{chain}"));
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "m@x".into(),
            omni: format!("0x{}", "77".repeat(32)),
            j1: "eyJ.fake.jwt".into(),
            wallet: "0xW".into(),
        });
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: "0xdkh".into(),
            operator_omni: format!("0x{}", "77".repeat(32)),
            tx_hash: None,
            account: None,
        });
        seed_actor_async(&state).await;
        state.caps.write().await.insert(
            "agent-folotoy".into(),
            vec![ApiCapToken {
                id: "cap-1".into(),
                cap: "memory:read".into(),
                scope: "family".into(),
                ttl: "900s".into(),
                minted: "now".into(),
                danger: None,
            }],
        );
        state.enroll.write().await.registered.insert(
            "user-1".into(),
            RegisteredCredential {
                credential_id_b64: "Y3JlZA".into(),
                registered_at_unix: 1,
            },
        );

        let resp = master_reset(State(state.clone())).await.0;
        let fleet = resp.get("fleet").expect("fleet in reset response");
        assert_eq!(fleet["pending_declined"], 2);
        assert_eq!(fleet["agents_revoked"].as_array().unwrap().len(), 1);
        assert_eq!(fleet["agents_revoked"][0]["label"], "FoloToy bear");
        assert_eq!(
            fleet["failures"].as_array().unwrap().len(),
            0,
            "no failures expected: {fleet}"
        );

        assert!(state.actors.read().await.is_empty(), "actors cleared");
        assert!(state.caps.read().await.is_empty(), "caps cleared");
        let os = onboarding_state(State(state.clone())).await.0;
        assert_eq!(os.k11, "none", "enroll store cleared");
        assert_eq!(os.chain, "none", "registered master cleared");
        let audit = state.audit.read().await;
        assert!(
            audit
                .iter()
                .any(|e| e.kind == "device.revoked" && e.detail.contains("fleet teardown")),
            "per-agent revocation audit row"
        );
    }

    #[tokio::test]
    async fn master_reset_surfaces_unrevoked_agents_when_chain_unconfigured() {
        // No chain script + no broker: the reset still clears local state, but
        // the response must LOUDLY carry what could not be torn down remotely.
        let state = make_state();
        seed_actor_async(&state).await;

        let resp = master_reset(State(state.clone())).await.0;
        let fleet = resp.get("fleet").expect("fleet in reset response");
        assert_eq!(fleet["pending_declined"], 0);
        assert_eq!(fleet["agents_revoked"].as_array().unwrap().len(), 0);
        let failures = fleet["failures"].as_array().unwrap();
        assert!(
            failures
                .iter()
                .any(|f| f.as_str().unwrap_or("").contains("NOT revoked on chain")),
            "unrevoked agents must be surfaced: {fleet}"
        );
        assert!(state.actors.read().await.is_empty(), "actors still cleared");
        assert_eq!(onboarding_state(State(state)).await.0.k11, "none");
    }

    // ─── issue #233: actor tree reconstructed from chain after a restart ─────

    const T233_OMNI: &str = "aa"; // repeated ×32 → the operator omni
    const T233_AGENT_OMNI: &str = "bb";
    const T233_REVOKED_OMNI: &str = "cc";
    const T233_MASTER_HASH: &str = "11";
    const T233_AGENT_HASH: &str = "22";
    const T233_REVOKED_HASH: &str = "33";

    /// Stub JSON-RPC chain for #233: ONE operator with a master device, one
    /// active agent, one revoked agent. Dispatches `eth_call` on the calldata
    /// selector (+ the device hash argument for `getDevice`).
    async fn spawn_chain_stub() -> std::net::SocketAddr {
        spawn_chain_stub_with_master_model(false).await
    }

    /// `master_has_code: true` answers `eth_getCode` with non-empty bytecode,
    /// so the #260 reset guard classifies the master as a passkey P256Account;
    /// `false` (the [`spawn_chain_stub`] default) answers `0x` — a legacy EOA.
    async fn spawn_chain_stub_with_master_model(master_has_code: bool) -> std::net::SocketAddr {
        fn word(hex2: &str) -> String {
            hex2.repeat(32)
        }
        fn u8_word(v: u8) -> String {
            format!("{:0>64}", format!("{v:x}"))
        }
        fn device_entry(operator: &str, actor: &str, tier: u8, revoked: u8) -> String {
            // 11 static words: operatorOmni, actorOmni, k11CredId, k11RpIdHash,
            // k11PubX, k11PubY, tier, roles, registeredAt, lastSignCount, revoked.
            format!(
                "0x{}{}{}{}{}{}{}{}{}{}{}",
                word(operator),
                word(actor),
                "0".repeat(64),
                "0".repeat(64),
                "0".repeat(64),
                "0".repeat(64),
                u8_word(tier),
                u8_word(4), // ROLE_CAP_MINT-ish; unused by the parser
                u8_word(9), // registeredAt
                u8_word(0),
                u8_word(revoked),
            )
        }
        let app = Router::new().route(
            "/",
            post(move |Json(body): Json<serde_json::Value>| async move {
                if body["method"].as_str() == Some("eth_getCode") {
                    let code = if master_has_code { "0x60806040" } else { "0x" };
                    return Json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": code }));
                }
                let data = body["params"][0]["data"].as_str().unwrap_or("");
                let sel_devices = chain_selector("getOperatorDevices(bytes32)");
                let sel_device = chain_selector("getDevice(bytes32)");
                let sel_master = chain_selector("operatorMasterWallet(bytes32)");
                let sel_scope = chain_selector("getScope(bytes32,bytes32)");
                let result = if data.starts_with(&format!("0x{sel_scope}")) {
                    // Scope { services: [keccak("memory:family")], readOnly:
                    // false, caps 0, updatedAt 9, exists: true } → the agent
                    // has family read+write on chain.
                    let fam =
                        hex::encode(agentkeys_core::device_crypto::keccak256(b"memory:family"));
                    format!(
                        "0x{:0>64x}{:0>64x}{}{}{}{}{}{:0>64x}{:0>64x}{:0>64x}{fam}",
                        0x20,           // struct offset
                        0x100,          // services offset within the struct (after the 8-word head)
                        "0".repeat(64), // readOnly = false
                        "0".repeat(64), // maxPerCall
                        "0".repeat(64), // maxPerPeriod
                        "0".repeat(64), // maxTotal
                        "0".repeat(64), // periodSeconds
                        9,              // updatedAt
                        1,              // exists = true
                        1,              // services.len
                    )
                } else if data.starts_with(&format!("0x{sel_devices}")) {
                    // offset, len=3, [master_hash, agent_hash, revoked_hash]
                    format!(
                        "0x{:0>64x}{:0>64x}{}{}{}",
                        0x20,
                        3,
                        T233_MASTER_HASH.repeat(32),
                        T233_AGENT_HASH.repeat(32),
                        T233_REVOKED_HASH.repeat(32),
                    )
                } else if data.starts_with(&format!("0x{sel_device}")) {
                    let arg = &data[10..];
                    if arg.starts_with(&T233_MASTER_HASH.repeat(32)) {
                        device_entry(T233_OMNI, T233_OMNI, 1, 0)
                    } else if arg.starts_with(&T233_AGENT_HASH.repeat(32)) {
                        device_entry(T233_OMNI, T233_AGENT_OMNI, 2, 0)
                    } else {
                        device_entry(T233_OMNI, T233_REVOKED_OMNI, 2, 1)
                    }
                } else if data.starts_with(&format!("0x{sel_master}")) {
                    format!("0x{:0>24}{}", "", "44".repeat(20))
                } else {
                    "0x".into()
                };
                Json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// Point a freshly-built state's chain profile at a test RPC stub — a
    /// direct field override on the still-unshared `Arc`, NEVER
    /// `$AGENTKEYS_CHAIN_PROFILE_FILE`. Env is process-global and the suite
    /// runs on parallel threads: a `set_var` here leaks into every concurrent
    /// `build_state`, whose state then eth_calls a stub whose owning test —
    /// runtime, server task, listener — may already be gone (the intermittent
    /// `master_reset_tears_down_the_fleet` connection-refused flake), or worse,
    /// still alive and serving a foreign fleet.
    fn set_chain_rpc(state: &mut SharedUiBridgeState, rpc: &str) {
        Arc::get_mut(state)
            .expect("set_chain_rpc must run before the state Arc is cloned")
            .chain_profile
            .rpc
            .http = rpc.to_string();
    }

    #[tokio::test]
    async fn list_actors_reconstructs_fleet_from_chain_after_restart() {
        // Post-restart: actors map EMPTY, registered_master rehydrated (account
        // unknown). list_actors must rebuild from chain — master row synthesized
        // (account backfilled from operatorMasterWallet), active agent restored
        // with its device hash, revoked agent excluded.
        let addr = spawn_chain_stub().await;
        let mut state = make_state_real(None);
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
            operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
            tx_hash: None,
            account: None, // lost on restart — must be backfilled from chain
        });

        let resp = list_actors(State(state.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actors_arr = json["actors"].as_array().unwrap();
        assert_eq!(actors_arr.len(), 2, "master + 1 active agent: {json}");
        assert_eq!(actors_arr[0]["role"], "master");
        assert_eq!(
            actors_arr[0]["account_address"],
            format!("0x{}", "44".repeat(20)),
            "master P256Account backfilled from operatorMasterWallet"
        );
        assert_eq!(actors_arr[1]["role"], "agent");
        assert_eq!(
            actors_arr[1]["device_key_hash"],
            format!("0x{}", T233_AGENT_HASH.repeat(32))
        );
        // The on-chain grant (memory:family) is mirrored into the permission panel's
        // data source as READ (the DENY-everywhere incident). A memory grant is
        // shared-READ only; inbox-WRITE is the DISTINCT inbox:<ns> grant (#339),
        // absent here — so write stays false.
        assert_eq!(actors_arr[1]["scope"]["family"]["read"], true);
        assert_eq!(actors_arr[1]["scope"]["family"]["write"], false);
        assert!(
            actors_arr[1]["scope"].get("personal").is_none(),
            "ungranted namespaces stay absent"
        );
        assert!(
            !json.to_string().contains(&T233_REVOKED_OMNI.repeat(32)),
            "revoked device must be excluded"
        );
        assert_eq!(
            state
                .registered_master
                .read()
                .await
                .as_ref()
                .unwrap()
                .account
                .as_deref(),
            Some(format!("0x{}", "44".repeat(20)).as_str())
        );
    }

    #[tokio::test]
    async fn master_register_invalidates_a_poisoned_fleet_sync() {
        // The empty-actor-page bug (Codex adversarial-review finding #1): the
        // lazy sync was latched "synced" while the master was UNREGISTERED (an
        // empty reconcile during the reset→re-onboard window), then the master
        // registers. Routing every register through `mark_master_registered`
        // bumps the fleet generation, so the next `/v1/actors` read MUST
        // re-reconcile and surface the master — even though the latch had
        // claimed it was already synced. (Before the fix, the stale latch made
        // `list_actors` skip reconcile and return `[]` forever.)
        use std::sync::atomic::Ordering;
        let addr = spawn_chain_stub().await;
        let mut state = make_state_real(None);
        set_chain_rpc(&mut state, &format!("http://{addr}"));

        // Poison the latch exactly as an empty reconcile would: claim the
        // (empty) in-memory map is current as of the latest generation.
        state
            .fleet_synced_gen
            .store(state.fleet_gen.load(Ordering::Relaxed), Ordering::Relaxed);

        // The master registers — the production transition every register path
        // now funnels through.
        mark_master_registered(
            &state,
            RegisteredMaster {
                device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
                operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
                tx_hash: None,
                account: None,
            },
        )
        .await;

        let resp = list_actors(State(state.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let actors_arr = json["actors"].as_array().unwrap();
        assert!(
            actors_arr.iter().any(|a| a["role"] == "master"),
            "master row must surface after register despite the poisoned latch: {json}"
        );
    }

    #[tokio::test]
    async fn stale_reconcile_cannot_mask_a_newer_invalidation() {
        // Models the [high] TOCTOU at the atomic level: reconcile A observes
        // generation G; an invalidation (e.g. a master register) bumps to G+1
        // mid-read; then A completes and advances `fleet_synced_gen` only to the
        // OBSERVED G via fetch_max. The next read must still see synced(G) <
        // gen(G+1) and re-sync — a stale EMPTY read can never latch over the
        // newer register.
        use std::sync::atomic::Ordering;
        let state = make_state();
        let observed = state.fleet_gen.load(Ordering::Relaxed); // reconcile A starts here
        invalidate_fleet_sync(&state); // a register lands mid-read
        state
            .fleet_synced_gen
            .fetch_max(observed, Ordering::Release); // A latches its OLD gen
        assert!(
            state.fleet_gen.load(Ordering::Relaxed)
                > state.fleet_synced_gen.load(Ordering::Relaxed),
            "a reconcile that observed an older generation leaves a re-sync pending"
        );
    }

    #[tokio::test]
    async fn master_reset_revokes_chain_reconstructed_agents_by_hash() {
        // Restart-then-reset: the in-memory map is EMPTY but the chain still
        // holds an active agent. Reset must reconstruct first (#233) and revoke
        // that agent BY DEVICE KEY HASH (no ~/.agentkeys/agents/<label>.json
        // exists for a reconstructed actor).
        let addr = spawn_chain_stub().await;
        let tmp = tempfile::tempdir().unwrap();
        let args_file = tmp.path().join("revoke-args.txt");
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            format!(
                "#!/usr/bin/env bash\necho \"$@\" >> {}\necho '{{\"ok\":true,\"tx_hash\":\"0xrevoketx\"}}'\n",
                args_file.display()
            ),
        )
        .unwrap();
        let mut state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(tmp.path().join("master.sh").to_string_lossy().into_owned()),
            None,
        )
        .unwrap();
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
            operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
            tx_hash: None,
            account: None,
        });
        assert!(state.actors.read().await.is_empty(), "restart: empty map");

        let resp = master_reset(State(state.clone())).await.0;
        let fleet = resp.get("fleet").expect("fleet in reset response");
        assert_eq!(
            fleet["agents_revoked"].as_array().unwrap().len(),
            1,
            "the chain-reconstructed agent must be revoked: {fleet}"
        );
        let args = std::fs::read_to_string(&args_file).expect("revoke script invoked");
        assert!(
            args.contains(&format!(
                "--device-key-hash 0x{}",
                T233_AGENT_HASH.repeat(32)
            )),
            "revoke keyed on the on-chain hash, got: {args}"
        );
        assert!(state.actors.read().await.is_empty(), "fleet cleared");
    }

    #[tokio::test]
    async fn master_reset_aborts_for_account_master_with_bound_agents() {
        // #260: an account-master (operatorMasterWallet has code) with an agent
        // still ACTIVE on chain must NOT unbind — no EOA script can sign
        // revokeAgentDevice for it, and clearing operatorMasterWallet first
        // would strand the binding. The reset returns ok:false +
        // needs_fleet_revoke and mutates NOTHING (no script call, actors kept,
        // master binding kept) so the UI can run the one-Touch-ID fleet revoke
        // and retry.
        let addr = spawn_chain_stub_with_master_model(true).await;
        let tmp = tempfile::tempdir().unwrap();
        let args_file = tmp.path().join("revoke-args.txt");
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            format!(
                "#!/usr/bin/env bash\necho \"$@\" >> {}\necho '{{\"ok\":true,\"tx_hash\":\"0xrevoketx\"}}'\n",
                args_file.display()
            ),
        )
        .unwrap();
        let mut state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(tmp.path().join("master.sh").to_string_lossy().into_owned()),
            None,
        )
        .unwrap();
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
            operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
            tx_hash: None,
            account: None,
        });

        let resp = master_reset(State(state.clone())).await.0;
        assert_eq!(resp["ok"], false, "reset must refuse the unbind: {resp}");
        assert_eq!(resp["needs_fleet_revoke"], true);
        assert_eq!(resp["onchain"]["status"], "aborted");
        assert_eq!(
            resp["onchain"]["reason"],
            "account-master-agents-still-bound"
        );
        let bound = resp["fleet"]["agents_still_bound"]
            .as_array()
            .expect("agents_still_bound in abort response");
        assert_eq!(bound.len(), 1, "the active chain agent: {resp}");
        assert_eq!(
            bound[0]["device_key_hash"],
            format!("0x{}", T233_AGENT_HASH.repeat(32))
        );
        assert!(
            !args_file.exists(),
            "the EOA revoke script must never run for an account master"
        );
        assert!(
            state.registered_master.read().await.is_some(),
            "master binding kept — nothing mutated on abort"
        );
        assert!(
            !state.actors.read().await.is_empty(),
            "actor map kept for the post-ceremony retry"
        );
    }

    #[tokio::test]
    async fn master_reset_skips_agents_already_revoked_on_chain_without_script() {
        // #260: after the pre-reset Touch-ID fleet revoke, agents arrive at the
        // teardown already revoked on chain. The teardown must report them
        // (already_revoked, audit row) WITHOUT shelling the EOA script for
        // them, and proceed with the rest of the reset.
        let addr = spawn_chain_stub().await; // EOA master — script allowed
        let tmp = tempfile::tempdir().unwrap();
        let args_file = tmp.path().join("revoke-args.txt");
        std::fs::write(
            tmp.path().join("heima-device-revoke.sh"),
            format!(
                "#!/usr/bin/env bash\necho \"$@\" >> {}\necho '{{\"ok\":true,\"tx_hash\":\"0xrevoketx\"}}'\n",
                args_file.display()
            ),
        )
        .unwrap();
        let mut state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(tmp.path().join("master.sh").to_string_lossy().into_owned()),
            None,
        )
        .unwrap();
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
            operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
            tx_hash: None,
            account: None,
        });
        // A locally-known agent whose on-chain entry is REVOKED (the stub's
        // 0x33… device) — e.g. the fleet-revoke ceremony landed before reset.
        let revoked_local = ApiActor {
            device_key_hash: Some(format!("0x{}", T233_REVOKED_HASH.repeat(32))),
            ..seed_actor_async(&state).await
        };
        state
            .actors
            .write()
            .await
            .insert(revoked_local.id.clone(), revoked_local);

        let resp = master_reset(State(state.clone())).await.0;
        assert_eq!(resp["ok"], true, "reset proceeds: {resp}");
        let revoked = resp["fleet"]["agents_revoked"]
            .as_array()
            .expect("agents_revoked");
        // Two rows: the pre-revoked local agent (skip, already_revoked) and the
        // chain-reconstructed ACTIVE agent (script revoke).
        assert_eq!(revoked.len(), 2, "{resp}");
        assert!(
            revoked
                .iter()
                .any(|r| r["already_revoked"] == true && r["tx_hash"].is_null()),
            "the pre-revoked agent rides as a chain-verified skip: {resp}"
        );
        let args = std::fs::read_to_string(&args_file).expect("script ran for the active agent");
        assert!(
            args.contains(&T233_AGENT_HASH.repeat(32)),
            "active agent revoked via script: {args}"
        );
        assert!(
            !args.contains(&T233_REVOKED_HASH.repeat(32)),
            "already-revoked agent must NOT hit the script: {args}"
        );
        assert!(state
            .audit
            .read()
            .await
            .iter()
            .any(|e| e.kind == "device.revoked" && e.detail.contains("already revoked")));
    }

    #[tokio::test]
    async fn ack_pairing_surfaces_the_accepted_agent() {
        // The E7 accept path's final ack must insert the freshly-bound agent
        // into the actor tree (with the pending row's REAL label + device hash)
        // and un-latch the chain sync — without this, an accepted agent stayed
        // invisible until a daemon restart (real 2026-06-10 incident).
        let app = Router::new()
            .route(
                "/v1/agent/pending-bindings",
                axum::routing::get(|| async {
                    Json(serde_json::json!({ "pending": [{
                        "request_id": "req-9",
                        "label": "hermes",
                        "child_omni": format!("0x{}", "dd".repeat(32)),
                        "device_key_hash": "ee".repeat(32),
                        "device_pubkey": "0xPUBKEY",
                    }] }))
                }),
            )
            .route(
                "/v1/agent/pending-bindings/ack",
                post(|Json(b): Json<serde_json::Value>| async move {
                    assert_eq!(b.get("request_id").and_then(|v| v.as_str()), Some("req-9"));
                    Json(serde_json::json!({ "ok": true }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some(format!("http://{addr}")),
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            None,
            None,
        )
        .unwrap();
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "m@x".into(),
            omni: format!("0x{}", "77".repeat(32)),
            j1: "eyJ.fake.jwt".into(),
            wallet: "0xW".into(),
        });
        // Simulate "already synced": mark the in-memory map current as of the
        // latest fleet generation, so we can prove ack INVALIDATES it.
        state.fleet_synced_gen.store(
            state.fleet_gen.load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );

        let resp = ack_pairing(
            State(state.clone()),
            Json(serde_json::json!({ "request_id": "req-9" })),
        )
        .await;
        assert!(resp.status().is_success(), "ack forwarded ok");

        let actors = state.actors.read().await;
        let agent = actors.get("agent-hermes").expect("accepted agent surfaced");
        assert_eq!(agent.label, "hermes");
        assert_eq!(agent.role, "agent");
        assert_eq!(
            agent.device_key_hash.as_deref(),
            Some(format!("0x{}", "ee".repeat(32)).as_str()),
            "hash normalized to 0x form"
        );
        drop(actors);
        assert!(
            state.fleet_gen.load(std::sync::atomic::Ordering::Relaxed)
                > state
                    .fleet_synced_gen
                    .load(std::sync::atomic::Ordering::Relaxed),
            "chain sync invalidated so the next read re-reconciles"
        );
    }

    // ─── issue #424 §1: the binding manifest ────────────────────────────────

    #[test]
    fn binding_manifest_upsert_normalizes_and_preserves_kind() {
        let mut m = BindingManifest::default();
        m.upsert(BindingManifestEntry {
            actor_omni: format!("0X{}", "AB".repeat(32)), // mixed case, 0X
            device_key_hash: "cd".repeat(32),             // bare (no 0x)
            label: "cam-frontdoor".into(),
            kind: "device".into(),
            granted_service_names: vec!["channel-pub:frontdoor".into()],
            updated_at: 1,
            ..Default::default()
        });
        // Normalized on write; found by omni AND by device hash, any casing.
        let by_omni = m
            .entry_for(&format!("0x{}", "ab".repeat(32)), "")
            .expect("by omni");
        assert_eq!(by_omni.actor_omni, format!("0x{}", "ab".repeat(32)));
        assert_eq!(by_omni.device_key_hash, format!("0x{}", "cd".repeat(32)));
        assert!(m
            .entry_for(&format!("0x{}", "99".repeat(32)), &"CD".repeat(32))
            .is_some());

        // A scope re-grant (empty kind/label — the submit proxy knows only the
        // services) must UPDATE the names but never flip the kind or drop the
        // label/device hash.
        m.upsert(BindingManifestEntry {
            actor_omni: format!("0x{}", "ab".repeat(32)),
            device_key_hash: String::new(),
            label: String::new(),
            kind: String::new(),
            granted_service_names: vec![
                "channel-pub:frontdoor".into(),
                "channel-sub:frontdoor".into(),
            ],
            updated_at: 2,
            ..Default::default()
        });
        assert_eq!(m.bindings.len(), 1, "upsert, not append");
        let e = m.entry_for(&format!("0x{}", "ab".repeat(32)), "").unwrap();
        assert_eq!(e.kind, "device", "kind preserved across re-grants");
        assert_eq!(e.label, "cam-frontdoor", "label preserved");
        assert_eq!(e.device_key_hash, format!("0x{}", "cd".repeat(32)));
        assert_eq!(e.granted_service_names.len(), 2);

        // A NEW entry arriving via a scope commit (no kind known) derives the
        // kind from its grants with the SAME predicate as the D9 spawn gate.
        m.upsert(BindingManifestEntry {
            actor_omni: format!("0x{}", "ee".repeat(32)),
            device_key_hash: String::new(),
            label: String::new(),
            kind: String::new(),
            granted_service_names: vec!["memory:travel".into()],
            updated_at: 3,
            ..Default::default()
        });
        assert_eq!(
            m.entry_for(&format!("0x{}", "ee".repeat(32)), "")
                .unwrap()
                .kind,
            "delegate"
        );
        // Serde round-trip (the config-doc payload).
        let bytes = serde_json::to_vec(&m).unwrap();
        let back: BindingManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.bindings.len(), 2);
        assert_eq!(
            back.entry_for(&m.bindings[0].actor_omni, "").unwrap().kind,
            "device"
        );
    }

    #[tokio::test]
    async fn ack_pairing_persists_the_binding_manifest_entry() {
        // #424 §1 — the accept is the durability boundary: a device accept must
        // land its kind + granted NAMES in the binding manifest (cache-only
        // here — Config unconfigured — but the same write path).
        let app = Router::new()
            .route(
                "/v1/agent/pending-bindings",
                axum::routing::get(|| async {
                    Json(serde_json::json!({ "pending": [{
                        "request_id": "req-dev",
                        "label": "cam-frontdoor",
                        "child_omni": format!("0x{}", "dd".repeat(32)),
                        "device_key_hash": "ee".repeat(32),
                        "device_pubkey": "0xPUBKEY",
                    }] }))
                }),
            )
            .route(
                "/v1/agent/pending-bindings/ack",
                post(|| async { Json(serde_json::json!({ "ok": true })) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            Some(format!("http://{addr}")),
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            "us-east-1".into(),
            None,
            None,
            None,
        )
        .unwrap();
        *state.onboarding_session.write().await = Some(OnboardingSession {
            email: "m@x".into(),
            omni: format!("0x{}", "77".repeat(32)),
            j1: "eyJ.fake.jwt".into(),
            wallet: "0xW".into(),
        });
        // The accept proxy stashed the card's FINAL grant set + device flag.
        state.accept_grants_by_request.write().await.insert(
            "req-dev".into(),
            (vec!["channel-pub:frontdoor".into()], true),
        );

        let resp = ack_pairing(
            State(state.clone()),
            Json(serde_json::json!({ "request_id": "req-dev" })),
        )
        .await;
        assert!(resp.status().is_success());

        let actors = state.actors.read().await;
        let agent = actors.get("agent-cam-frontdoor").expect("surfaced");
        assert_eq!(agent.vendor, "device");
        assert_eq!(
            agent.services.as_deref(),
            Some(&["channel-pub:frontdoor".to_string()][..])
        );
        drop(actors);

        let manifest = state
            .binding_manifest
            .read()
            .await
            .clone()
            .expect("manifest cached by the ack upsert");
        let e = manifest
            .entry_for(&format!("0x{}", "dd".repeat(32)), "")
            .expect("entry for the accepted device");
        assert_eq!(e.kind, "device");
        assert_eq!(e.label, "cam-frontdoor");
        assert_eq!(e.device_key_hash, format!("0x{}", "ee".repeat(32)));
        assert_eq!(e.granted_service_names, vec!["channel-pub:frontdoor"]);
    }

    #[tokio::test]
    async fn fleet_reconcile_hydrates_kind_and_names_from_the_binding_manifest() {
        // #424 §1 acceptance — the reproduced 2026-07-12 bug: after a daemon
        // restart the chain-reconstructed device row lost its kind + channel
        // names (`services: null` → filed under delegates). With a manifest
        // entry the restored row must carry label, `vendor:"device"` and the
        // granted service NAMES — deterministically, no hash-guessing.
        let addr = spawn_chain_stub().await;
        let mut state = make_state_real(None);
        set_chain_rpc(&mut state, &format!("http://{addr}"));
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: format!("0x{}", T233_MASTER_HASH.repeat(32)),
            operator_omni: format!("0x{}", T233_OMNI.repeat(32)),
            tx_hash: None,
            account: None,
        });
        // The durable manifest (pre-seeded cache — the same doc the config
        // class serves in prod) knows the stub's active agent is a DEVICE.
        let mut manifest = BindingManifest::default();
        manifest.upsert(BindingManifestEntry {
            actor_omni: format!("0x{}", T233_AGENT_OMNI.repeat(32)),
            device_key_hash: format!("0x{}", T233_AGENT_HASH.repeat(32)),
            label: "cam-frontdoor".into(),
            kind: "device".into(),
            granted_service_names: vec!["channel-pub:frontdoor".into()],
            updated_at: 1,
            ..Default::default()
        });
        *state.binding_manifest.write().await = Some(manifest);

        let resp = list_actors(State(state.clone())).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let agent = json["actors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["role"] == "agent")
            .expect("restored agent")
            .clone();
        assert_eq!(agent["label"], "cam-frontdoor", "real label restored");
        assert_eq!(agent["id"], "agent-cam-frontdoor");
        assert_eq!(
            agent["vendor"], "device",
            "device kind survives the restart"
        );
        assert_eq!(agent["device"], "channel-endpoint device (§10.2)");
        let services: Vec<String> = agent["services"]
            .as_array()
            .expect("services populated after restart (the #424 §1 bug)")
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        assert!(services.contains(&"channel-pub:frontdoor".to_string()));
    }

    #[tokio::test]
    async fn revoke_cap_removes_only_matching_cap_and_emits_audit() {
        let state = make_state();
        seed_actor_async(&state).await;
        state.caps.write().await.insert(
            "agent-folotoy".into(),
            vec![
                ApiCapToken {
                    id: "cap-1".into(),
                    cap: "memory:read".into(),
                    scope: "family".into(),
                    ttl: "900s".into(),
                    minted: "now".into(),
                    danger: None,
                },
                ApiCapToken {
                    id: "cap-2".into(),
                    cap: "payment:execute".into(),
                    scope: "p≤5".into(),
                    ttl: "60s".into(),
                    minted: "now".into(),
                    danger: Some(true),
                },
            ],
        );

        let _ = revoke_cap(
            State(state.clone()),
            Path("agent-folotoy".into()),
            Json(RevokeCapRequest {
                cap: "memory:read".into(),
                intent_text: "Revoke memory:read".into(),
            }),
        )
        .await
        .unwrap();

        let caps = state.caps.read().await;
        let remaining = caps.get("agent-folotoy").unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].cap, "payment:execute");
        let audit = state.audit.read().await;
        assert!(audit.iter().any(|e| e.kind == "cap.revoked"));
    }

    #[tokio::test]
    async fn dev_seed_populates_all_collections() {
        let state = make_state();
        let resp = dev_seed(
            State(state.clone()),
            Json(DevSeedRequest {
                actors: vec![ApiActor {
                    id: "seed-1".into(),
                    omni: "x".into(),
                    omni_hex: "x".into(),
                    label: "seed".into(),
                    role: "agent".into(),
                    parent: Some("master".into()),
                    derivation: "//seed".into(),
                    device: "".into(),
                    device_pubkey: "".into(),
                    last_active: "now".into(),
                    status: "ok".into(),
                    vendor: "".into(),
                    k11: false,
                    device_key_hash: None,
                    scope: None,
                    scope_unknown_service_ids: None,
                    payment_cap: None,
                    time_window: None,
                    services: None,
                    account_address: None,
                    account_type: None,
                    preset_id: None,
                    memory_ns: None,
                }],
                caps: HashMap::new(),
                workers: vec![ApiWorker {
                    id: "memory".into(),
                    title: "memory-service".into(),
                    host: "memory.example.invalid".into(),
                    desc: "".into(),
                    calls_today: 100,
                    calls_hour: 10,
                    p50: 30,
                    p95: 100,
                    cap: "mem:r".into(),
                    by_actor: vec![],
                }],
                anchor: Some(ApiAnchorStatus {
                    last_anchor_at: 100,
                    next_anchor_in: 0,
                    recent: vec![],
                }),
                audit: vec![],
                master_memory: vec![],
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(state.actors.read().await.len(), 1);
        assert_eq!(state.workers.read().await.len(), 1);
        assert_eq!(state.anchor.read().await.last_anchor_at, 100);
    }

    fn mem_entry(ns: &str, key: &str, body: &str) -> ApiMemoryEntry {
        ApiMemoryEntry {
            ns: ns.into(),
            key: key.into(),
            title: format!("{key}.md"),
            bytes: body.len() as u64,
            version: "v2".into(),
            updated: "just now".into(),
            preview: body.chars().take(40).collect(),
            body: body.into(),
            content_hash: String::new(),
            kind: ContextKind::Knowledge,
        }
    }

    #[tokio::test]
    async fn master_memory_empty_by_default() {
        let state = make_state();
        let resp = list_master_memory(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn plant_then_replant_is_idempotent_dedup() {
        let state = make_state();
        let entries = vec![
            mem_entry("personal", "profile", "name: Kevin"),
            mem_entry("travel", "chengdu", "trip May 25-29"),
        ];

        // First plant: both land.
        let r1 = plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: entries.clone(),
            },
        )
        .await
        .unwrap();
        assert_eq!(r1.planted, 2);
        assert_eq!(r1.skipped, 0);
        assert_eq!(r1.total, 2);
        assert_eq!(state.master_memory.read().await.len(), 2);

        // Re-plant the SAME content: 0 planted, 2 skipped (dedup by content_hash).
        let r2 = plant_master_memory_inner(&state, MasterMemoryPlantRequest { entries })
            .await
            .unwrap();
        assert_eq!(r2.planted, 0);
        assert_eq!(r2.skipped, 2);
        assert_eq!(r2.total, 2);
        assert_eq!(
            state.master_memory.read().await.len(),
            2,
            "re-plant must not duplicate"
        );

        // Plant emits a memory.write audit row (only when something was planted).
        assert!(state
            .audit
            .read()
            .await
            .iter()
            .any(|e| e.kind == "memory.write"));
    }

    #[tokio::test]
    async fn plant_changed_body_adds_a_new_entry() {
        let state = make_state();
        let _ = plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![mem_entry("personal", "profile", "v1 body")],
            },
        )
        .await
        .unwrap();
        // Same ns/key but DIFFERENT body → different content_hash → a new entry.
        let r = plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![mem_entry("personal", "profile", "v2 body")],
            },
        )
        .await
        .unwrap();
        assert_eq!(r.planted, 1);
        assert_eq!(state.master_memory.read().await.len(), 2);
    }

    // ─── #201 Phase 4: taxonomy categories + per-ns array + lazy detail ───

    #[test]
    fn label_for_ns_titlecases() {
        assert_eq!(label_for_ns("travel"), "Travel");
        assert_eq!(label_for_ns("personal"), "Personal");
        assert_eq!(label_for_ns(""), "");
    }

    #[test]
    fn parse_stored_blob_reads_json_array() {
        let blob = r#"[{"key":"chengdu-trip","title":"Chengdu trip","body":"Apr 12-16","updated":"2026-04-02","bytes":9}]"#;
        let entries = parse_stored_blob(blob, "travel");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "chengdu-trip");
        assert_eq!(entries[0].body, "Apr 12-16");
    }

    #[test]
    fn parse_stored_blob_tolerates_legacy_single_body() {
        // A pre-#201 single-body blob (or an agent-written one) becomes a
        // one-element array keyed by the namespace — the read path never breaks.
        let entries = parse_stored_blob("Chengdu trip — Apr 12 to 16", "travel");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "travel");
        assert!(entries[0].body.contains("Chengdu"));
    }

    #[test]
    fn to_stored_from_stored_round_trip() {
        let e = mem_entry("travel", "chengdu", "trip body");
        let s = e.to_stored();
        assert_eq!(s.key, "chengdu");
        assert_eq!(s.body, "trip body");
        let back = ApiMemoryEntry::from_stored("travel", s);
        assert_eq!(back.ns, "travel");
        assert_eq!(back.key, "chengdu");
        assert_eq!(back.body, "trip body");
    }

    #[tokio::test]
    async fn list_master_memory_returns_categories_from_cache_fallback() {
        // No config_url ⇒ categories derive from the planted namespaces (sorted,
        // deduped, title-cased), with ZERO memory decryption.
        let state = make_state();
        plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![
                    mem_entry("travel", "chengdu", "trip"),
                    mem_entry("personal", "profile", "name: Kevin"),
                    mem_entry("travel", "customs", "customs note"),
                ],
            },
        )
        .await
        .unwrap();
        let resp = list_master_memory(State(state)).await.into_response();
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let cats = json["categories"].as_array().unwrap();
        assert_eq!(cats.len(), 2, "two distinct namespaces");
        assert_eq!(cats[0]["ns"], "personal");
        assert_eq!(cats[0]["label"], "Personal");
        assert_eq!(cats[1]["ns"], "travel");
    }

    #[tokio::test]
    async fn get_master_memory_entry_filters_ns_and_key() {
        let state = make_state();
        plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![
                    mem_entry("travel", "chengdu", "trip body"),
                    mem_entry("travel", "customs", "customs body"),
                    mem_entry("personal", "profile", "profile body"),
                ],
            },
        )
        .await
        .unwrap();
        // ns only → both travel entries (lazy detail, in-memory fallback).
        let all = get_master_memory_entry_inner(
            &state,
            &MemoryEntryQuery {
                ns: "travel".into(),
                key: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|e| e.ns == "travel"));
        // ns + key → exactly one entry.
        let one = get_master_memory_entry_inner(
            &state,
            &MemoryEntryQuery {
                ns: "travel".into(),
                key: Some("chengdu".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].key, "chengdu");
        assert_eq!(one[0].body, "trip body");
    }

    // ─── #201 Phase 4 codex fixes: durable merge + configured-Config surfacing ──

    fn stored(key: &str, body: &str) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: key.into(),
            title: key.into(),
            body: body.into(),
            updated: "2026-04-02".into(),
            bytes: body.len() as u64,
            version: default_stored_version(),
            kind: ContextKind::Knowledge,
        }
    }

    #[test]
    fn merge_preserves_durable_when_request_omits_them() {
        // codex finding 1: durable entries read back from S3 (e.g. after a daemon
        // restart, so they're ABSENT from the in-memory cache) MUST survive a
        // plant that only carries a new entry for the same namespace.
        let durable = vec![
            stored("chengdu-trip", "Apr 12-16"),
            stored("customs", "note"),
        ];
        let incoming = vec![mem_entry("travel", "anniversary", "dinner 2026-06-15")];
        let (merged, newly) = merge_stored_entries("travel", durable, &incoming);
        assert_eq!(newly, 1);
        assert_eq!(
            merged.len(),
            3,
            "durable entries preserved, new one appended"
        );
        let keys: Vec<&str> = merged.iter().map(|m| m.key.as_str()).collect();
        assert!(
            keys.contains(&"chengdu-trip")
                && keys.contains(&"customs")
                && keys.contains(&"anniversary")
        );
        assert!(
            keys.windows(2).all(|w| w[0] <= w[1]),
            "sorted by key for a stable blob"
        );
    }

    #[test]
    fn merge_dedups_identical_content() {
        // Re-planting content already in the durable blob is a no-op (newly == 0).
        let durable = vec![stored("profile", "name: Kevin")];
        let incoming = vec![mem_entry("personal", "profile", "name: Kevin")];
        let (merged, newly) = merge_stored_entries("personal", durable, &incoming);
        assert_eq!(newly, 0);
        assert_eq!(merged.len(), 1, "no duplicate appended");
    }

    #[test]
    fn merge_same_key_different_body_keeps_both() {
        // Content-hash identity: editing a key's body adds a 2nd entry (matches
        // the in-memory model) rather than dropping the original.
        let durable = vec![stored("profile", "v1")];
        let incoming = vec![mem_entry("personal", "profile", "v2")];
        let (merged, newly) = merge_stored_entries("personal", durable, &incoming);
        assert_eq!(newly, 1);
        assert_eq!(merged.len(), 2);
    }

    #[tokio::test]
    async fn list_master_memory_surfaces_configured_config_error() {
        // codex finding 2: a CONFIGURED-but-broken Config (--config-url set but
        // CONFIG_ROLE_ARN missing) must NOT silently fall back to the cache and
        // report an empty 200 — it surfaces as 502 so the operator sees it.
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            Some("https://config.example".into()), // config_url set
            None,                                  // CONFIG_ROLE_ARN missing → partial config
            None,                                  // classify_url
            None,                                  // sandbox_bridge_url — #390
            None,                                  // sandbox_bridge_token
            None,                                  // audit_worker_url
            "us-east-1".into(),
            None,
            None,
            None, // #220 master_session_store
        )
        .unwrap();
        let resp = list_master_memory(State(state)).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn plant_reports_taxonomy_status_unconfigured_in_fallback() {
        // No config_url ⇒ the plant's taxonomy_status is the honest "unconfigured"
        // (not a fake "ok"), so the caller knows the durable index wasn't touched.
        let state = make_state();
        let r = plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![mem_entry("travel", "chengdu", "trip")],
            },
        )
        .await
        .unwrap();
        assert_eq!(r.taxonomy_status, "unconfigured");
        assert_eq!(r.planted, 1);
    }

    #[tokio::test]
    async fn list_workers_empty_by_default() {
        let state = make_state();
        let resp = list_workers(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_worker_unknown_returns_404() {
        let state = make_state();
        let err = get_worker(State(state), Path("memory".into()))
            .await
            .expect_err("must 404");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0.reason, "worker-not-found");
    }

    #[tokio::test]
    async fn audit_buffer_caps_at_buffer_cap() {
        let state = make_state();
        for i in 0..(AUDIT_BUFFER_CAP + 25) {
            let evt = ApiAuditEvent {
                id: format!("e-{i}"),
                ts: format!("00:00:{:02}", i % 60),
                actor_id: "x".into(),
                actor: "x".into(),
                kind: "test.event".into(),
                detail: format!("event {i}"),
                chip: "audit".into(),
                sev: "ok".into(),
                tx_hash: None,
                audit_envelope_hashes: None,
            };
            push_audit(&state, evt).await;
        }
        let buf = state.audit.read().await;
        assert_eq!(
            buf.len(),
            AUDIT_BUFFER_CAP,
            "ring buffer must cap at AUDIT_BUFFER_CAP"
        );
    }

    #[tokio::test]
    async fn audit_stream_subscribes_before_emit_and_receives() {
        let state = make_state();
        let mut rx = state.audit_tx.subscribe();
        let evt = ApiAuditEvent {
            id: "e-stream-1".into(),
            ts: "00:00:00".into(),
            actor_id: "x".into(),
            actor: "x".into(),
            kind: "stream.test".into(),
            detail: "broadcast".into(),
            chip: "audit".into(),
            sev: "ok".into(),
            tx_hash: None,
            audit_envelope_hashes: None,
        };
        push_audit(&state, evt.clone()).await;
        let received = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("must receive within 200ms")
            .expect("must not error");
        assert_eq!(received.id, "e-stream-1");
    }

    #[tokio::test]
    async fn decode_audit_event_returns_real_calldata_and_envelope() {
        // #153: GET /v1/audit/:id/decode wires the real decoder. Assert the
        // registry-derived fields (selector/function/op_kind label) which are
        // independent of which chain profile CI resolves.
        let state = make_state();
        let evt = ApiAuditEvent {
            id: "dec-1".into(),
            ts: "00:00:00".into(),
            actor_id: "agent-x".into(),
            actor: "X".into(),
            kind: "audit.append".into(),
            detail: "stored a credential".into(),
            chip: "credentials".into(),
            sev: "ok".into(),
            tx_hash: None,
            audit_envelope_hashes: None,
        };
        push_audit(&state, evt).await;

        let resp = decode_audit_event(State(state.clone()), Path("dec-1".into()))
            .await
            .expect("decode must succeed");
        let v = resp.0;
        assert_eq!(v["tier"], serde_json::json!("tier-2"));
        assert_eq!(v["tx"]["to_contract"], serde_json::json!("CredentialAudit"));
        assert_eq!(
            v["tx"]["decoded"]["selector"],
            serde_json::json!("0xc1bf0e32")
        );
        assert_eq!(v["tx"]["decoded"]["function"], serde_json::json!("append"));
        assert_eq!(
            v["envelope"]["op_kind_label"],
            serde_json::json!("cred.store")
        );

        // unknown id → 404
        let err = decode_audit_event(State(state), Path("nope".into()))
            .await
            .unwrap_err();
        assert_eq!(err.0, StatusCode::NOT_FOUND);
    }

    /// #97: receipt extraction from broker submit responses — confirmed,
    /// pending, and junk shapes.
    #[test]
    fn submit_receipts_extracts_tx_and_envelope_hashes() {
        let confirmed = serde_json::json!({
            "ok": true, "tx_hash": "0xabc", "block_number": "0x1",
            "user_op_hash": "0xdef",
            "audit_envelope_hashes": ["0x11", "0x22"],
        });
        let (tx, hashes) = submit_receipts(&confirmed);
        assert_eq!(tx.as_deref(), Some("0xabc"));
        assert_eq!(hashes, Some(vec!["0x11".to_string(), "0x22".to_string()]));

        // pending: empty tx, no hashes → both None
        let pending = serde_json::json!({
            "ok": true, "tx_hash": "", "block_number": "",
            "user_op_hash": "0xdef", "pending": true,
        });
        assert_eq!(submit_receipts(&pending), (None, None));

        // empty hash array normalizes to None
        let empty = serde_json::json!({ "tx_hash": "0xabc", "audit_envelope_hashes": [] });
        let (tx, hashes) = submit_receipts(&empty);
        assert_eq!(tx.as_deref(), Some("0xabc"));
        assert_eq!(hashes, None);
    }

    /// #97: the overlay replaces the synthesized preview with the fetched
    /// envelope(s) and flips the provenance; an empty fetch is a no-op
    /// (preview survives a down audit worker).
    #[test]
    fn overlay_real_envelopes_replaces_preview() {
        use agentkeys_core::audit::{envelope_for, AuditOpKind, AuditResult, ScopeRevokeBody};

        let real = envelope_for(
            [0x33; 32],
            [0x22; 32],
            AuditOpKind::ScopeRevoke,
            ScopeRevokeBody {
                agent_omni: format!("0x{}", "33".repeat(32)),
            },
            AuditResult::Success,
            None,
            None,
        )
        .unwrap()
        .to_json();

        let mut base = serde_json::json!({
            "synthesized": true, "provenance": "preview",
            "envelope": { "op_kind_label": "synthetic" }, "tx": null,
        });
        overlay_real_envelopes(&mut base, vec![real.clone()], Some("0xfeed"));
        assert_eq!(base["synthesized"], serde_json::json!(false));
        assert_eq!(base["tx_hash"], serde_json::json!("0xfeed"));
        assert_eq!(
            base["envelope"]["op_kind_label"],
            serde_json::json!("scope.revoke")
        );
        assert_eq!(base["envelopes"].as_array().map(Vec::len), Some(1));
        assert!(base["provenance"].as_str().unwrap().starts_with("real"));

        // nothing fetched → preview untouched (tx still recorded)
        let mut untouched = serde_json::json!({ "synthesized": true, "envelope": null });
        overlay_real_envelopes(&mut untouched, Vec::new(), Some("0xfeed"));
        assert_eq!(untouched["synthesized"], serde_json::json!(true));
        assert_eq!(untouched["tx_hash"], serde_json::json!("0xfeed"));
        assert!(untouched.get("envelopes").is_none());
    }

    /// #97: an event carrying receipt hashes but an UNREACHABLE audit worker
    /// degrades to the synthesized preview (with the tx recorded) — the decode
    /// endpoint never hard-fails on worker downtime. Hermetic: 127.0.0.1:9 is
    /// a closed port, connection-refused instantly.
    #[tokio::test]
    async fn decode_with_unreachable_audit_worker_falls_back_to_preview() {
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None,                              // sandbox_bridge_url — #390
            None,                              // sandbox_bridge_token
            Some("http://127.0.0.1:9".into()), // audit_worker_url — closed port
            "us-east-1".into(),
            None,
            None,
            None,
        )
        .unwrap();
        let evt = ApiAuditEvent {
            id: "dec-real-1".into(),
            ts: "00:00:00".into(),
            actor_id: "master".into(),
            actor: "master".into(),
            kind: "scope.grant".into(),
            detail: "setScope committed on chain".into(),
            chip: "broker".into(),
            sev: "ok".into(),
            tx_hash: Some("0xfeed".into()),
            audit_envelope_hashes: Some(vec![format!("0x{}", "ab".repeat(32))]),
        };
        push_audit(&state, evt).await;

        let resp = decode_audit_event(State(state), Path("dec-real-1".into()))
            .await
            .expect("decode must succeed despite the unreachable worker");
        let v = resp.0;
        assert_eq!(
            v["synthesized"],
            serde_json::json!(true),
            "preview fallback"
        );
        assert_eq!(v["tx_hash"], serde_json::json!("0xfeed"));
        assert_eq!(
            v["envelope"]["op_kind_label"],
            serde_json::json!("scope.grant")
        );
    }

    #[tokio::test]
    async fn chain_info_serves_resolved_profile_and_contract_array() {
        let state = make_state();
        let name = state.chain_profile.name.clone();
        let chain_id = state.chain_profile.chain_id;
        let resp = chain_info(
            State(state),
            axum::extract::Query(ChainInfoQuery { chain: None }),
        )
        .await
        .expect("default chain_info never errors");
        let v = resp.0;
        assert_eq!(v["name"], serde_json::json!(name));
        assert_eq!(v["chainId"], serde_json::json!(chain_id));
        assert!(v["contracts"].is_array(), "contracts must be an array");
        assert_eq!(v["daemonChain"], serde_json::json!(name));
    }

    #[tokio::test]
    async fn chain_info_view_chain_and_list_back_the_web_switcher() {
        // #282 web chain switcher: ?chain= serves any built-in VIEW profile,
        // daemonChain always names the operational chain, unknown names 400,
        // and /v1/chain/list enumerates the built-ins.
        let state = make_state();
        let daemon_name = state.chain_profile.name.clone();
        let v = chain_info(
            State(state.clone()),
            axum::extract::Query(ChainInfoQuery {
                chain: Some("base".into()),
            }),
        )
        .await
        .expect("base is a built-in")
        .0;
        assert_eq!(v["chainId"], serde_json::json!(8453));
        assert_eq!(v["daemonChain"], serde_json::json!(daemon_name.clone()));

        let bad = chain_info(
            State(state.clone()),
            axum::extract::Query(ChainInfoQuery {
                chain: Some("doesnotexist".into()),
            }),
        )
        .await;
        assert!(bad.is_err(), "unknown view chain must be a 400");

        let list = chain_list(State(state)).await.0;
        assert_eq!(list["daemonChain"], serde_json::json!(daemon_name));
        let names: Vec<&str> = list["chains"]
            .as_array()
            .expect("chains array")
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        // Only chains with a deployed AgentKeys contract set are offered —
        // heima + base mainnet today; never the registry-less built-ins.
        assert!(names.contains(&"heima"), "heima listed: {names:?}");
        assert!(names.contains(&"base"), "base listed: {names:?}");
        assert!(
            !names.contains(&"ethereum"),
            "ethereum not supported: {names:?}"
        );
        assert!(!names.contains(&"anvil"), "anvil not supported: {names:?}");
        assert!(
            !names.contains(&"base-sepolia"),
            "base-sepolia not supported: {names:?}"
        );
    }

    // Convince clippy the sync helper isn't dead code.
    #[allow(dead_code)]
    fn _keep_seed_actor_alive(state: &SharedUiBridgeState) -> ApiActor {
        seed_actor(state)
    }

    // ─── Issue #196: on-chain master-device registration (K11-finish glue) ───

    fn write_temp_script(name: &str, body: &str) -> String {
        let path = std::env::temp_dir().join(format!("ak196-{name}.sh"));
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn run_register_script_parses_success() {
        // E7 build output: userop_hash + account the daemon stashes as pending.
        let script = write_temp_script(
            "ok",
            "#!/usr/bin/env bash\necho 'human log' >&2\n\
             echo '{\"ok\":true,\"userop_hash\":\"0xUOH\",\"account\":\"0xACC\",\"device_key_hash\":\"0xdeadbeef\",\"operator_omni\":\"0xfeed\"}'\n",
        );
        let json = run_register_script(&script, &["build"])
            .await
            .expect("parse success JSON");
        assert_eq!(
            json.get("userop_hash").and_then(|v| v.as_str()),
            Some("0xUOH")
        );
        assert_eq!(json.get("account").and_then(|v| v.as_str()), Some("0xACC"));
        assert_eq!(
            json.get("device_key_hash").and_then(|v| v.as_str()),
            Some("0xdeadbeef")
        );
    }

    #[tokio::test]
    async fn run_register_script_parses_idempotent_skip() {
        // Already-registered skip: a `skipped` marker, NO userop_hash/tx_hash.
        let script = write_temp_script(
            "skip",
            "#!/usr/bin/env bash\n\
             echo '{\"ok\":true,\"skipped\":\"already-registered\",\"device_key_hash\":\"0xabc\",\"operator_omni\":\"0xfeed\"}'\n",
        );
        let json = run_register_script(&script, &["build"])
            .await
            .expect("parse skip JSON");
        assert_eq!(
            json.get("skipped").and_then(|v| v.as_str()),
            Some("already-registered")
        );
        assert!(json.get("tx_hash").is_none());
    }

    #[tokio::test]
    async fn run_register_script_errors_on_nonzero_exit() {
        let script = write_temp_script(
            "fail",
            "#!/usr/bin/env bash\necho '    fail cast send failed' >&2\nexit 1\n",
        );
        let err = run_register_script(&script, &["build"])
            .await
            .expect_err("non-zero exit must be an Err");
        assert!(
            err.contains("exited") || err.contains("cast send failed"),
            "got: {err}"
        );
    }

    #[test]
    fn split_cose_xy_splits_uncompressed_pubkey() {
        let cose = format!("04{}{}", "ab".repeat(32), "cd".repeat(32));
        let (x, y) = split_cose_xy(&cose).expect("valid cose");
        assert_eq!(x, format!("0x{}", "ab".repeat(32)));
        assert_eq!(y, format!("0x{}", "cd".repeat(32)));
        assert!(split_cose_xy("0xdead").is_err(), "short pubkey rejected");
    }

    #[tokio::test]
    async fn onboarding_state_reports_chain_status() {
        let state = make_state();
        let before = onboarding_state(State(state.clone())).await;
        assert_eq!(before.0.chain, "none");
        *state.registered_master.write().await = Some(RegisteredMaster {
            device_key_hash: "0xabc".into(),
            operator_omni: "0xfeed".into(),
            tx_hash: Some("0xTX".into()),
            account: Some("0xACC0000000000000000000000000000000000001".into()),
        });
        let after = onboarding_state(State(state.clone())).await;
        assert_eq!(after.0.chain, "master-registered");
    }

    #[tokio::test]
    async fn finish_chain_register_skips_when_no_script() {
        // No --register-master-script ⇒ on-chain register disabled (dev/no-infra),
        // a CLEAN skip (chain "none", no error), not a failure.
        let state = make_state();
        let build = finish_chain_register(&state, "credid", Some("ignored")).await;
        assert!(build.register_userop_hash.is_none());
        assert_eq!(build.chain, "none");
        assert!(
            build.chain_error.is_none(),
            "no-script is a clean skip: {:?}",
            build.chain_error
        );
    }

    #[tokio::test]
    async fn finish_chain_register_errors_when_no_session() {
        // Script configured but no onboarding session ⇒ can't determine the omni
        // to register under; surfaces a chain_error (passkey still enrolled).
        let script = write_temp_script("nosession", "#!/usr/bin/env bash\necho '{}'\n");
        let state = build_state(
            "localhost",
            "http://localhost:3113",
            "AgentKeys Test",
            None,
            None,
            84532,
            None,
            None,
            None,
            None,
            None,
            None, // sandbox_bridge_url — #390, no sandbox in unit tests
            None, // sandbox_bridge_token
            None, // audit_worker_url — tests never fetch real envelopes by default
            "us-east-1".into(),
            None,
            Some(script),
            None, // #220 master_session_store
        )
        .unwrap();
        let build = finish_chain_register(&state, "credid", Some("ignored")).await;
        assert!(build.register_userop_hash.is_none());
        assert_eq!(build.chain, "none");
        assert!(
            build
                .chain_error
                .as_deref()
                .unwrap_or("")
                .contains("session"),
            "should explain the missing session: {:?}",
            build.chain_error
        );
    }

    // ─── #390 — per-kind curate gate + persona editor ────────────────────────

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("body is JSON")
    }

    #[test]
    fn curate_gate_per_kind_policy() {
        use axum::http::StatusCode;
        // knowledge — today's accept, no watermark needed.
        assert!(curate_gate(ContextKind::Knowledge, 10, None, "h").is_ok());
        // persona — NEVER inbox-adoptable (§16.2 item 3).
        let (status, reason) = curate_gate(ContextKind::Persona, 10, Some("h"), "h").unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(reason.contains("persona_not_inbox_adoptable"));
        // skill — requires the viewed-body watermark…
        let (status, _) = curate_gate(ContextKind::Skill, 10, None, "h").unwrap_err();
        assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
        // …the RIGHT watermark…
        let (status, _) = curate_gate(ContextKind::Skill, 10, Some("stale"), "h").unwrap_err();
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(curate_gate(ContextKind::Skill, 10, Some("h"), "h").is_ok());
        // …and the size cap.
        let (status, _) =
            curate_gate(ContextKind::Skill, SKILL_MAX_BYTES + 1, Some("h"), "h").unwrap_err();
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn plant_rejects_reserved_persona_namespace() {
        // #390 — the persona module is the single writer of `persona`; a plant
        // (or an inbox accept riding it) into that ns is a 400, even in the
        // in-memory fallback.
        let state = make_state();
        let mut entry = mem_entry(PERSONA_NAMESPACE, "soul:0xabc", "sneaky persona");
        entry.kind = ContextKind::Persona;
        let err = plant_master_memory_inner(
            &state,
            MasterMemoryPlantRequest {
                entries: vec![entry],
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("persona_ns_reserved"));
    }

    #[tokio::test]
    async fn persona_edit_get_rollback_delete_fallback_roundtrip() {
        // The full editor lifecycle on the in-memory fallback (no sandbox
        // configured): edit → v1, edit → v2, GET shows current+history,
        // rollback(1) → v3 with v1's body, delete removes everything.
        let state = make_state();
        let delegate = "0xAbCd1234";

        let resp = edit_master_persona(
            State(state.clone()),
            Json(PersonaEditRequest {
                delegate_omni: delegate.into(),
                body: "Be warm and brief.".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["version"], 1);
        // Sandbox unconfigured ⇒ stored canonically but NOT applied — surfaced,
        // never silent (the no-silent-fallback rule).
        assert_eq!(v["applied"], false);
        assert!(v["apply_detail"]
            .as_str()
            .unwrap()
            .contains("sandbox_unconfigured"));

        let resp = edit_master_persona(
            State(state.clone()),
            Json(PersonaEditRequest {
                delegate_omni: delegate.into(),
                body: "Be concise. 说中文。".into(),
            }),
        )
        .await;
        assert_eq!(body_json(resp).await["version"], 2);

        let resp = get_master_persona(
            State(state.clone()),
            axum::extract::Query(PersonaQuery {
                delegate: delegate.into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let view = body_json(resp).await;
        assert_eq!(view["current"]["version"], "v2");
        assert_eq!(view["current"]["kind"], "persona");
        assert_eq!(view["versions"].as_array().unwrap().len(), 1);
        assert_eq!(view["sandbox_configured"], false);

        let resp = rollback_master_persona(
            State(state.clone()),
            Json(PersonaRollbackRequest {
                delegate_omni: delegate.into(),
                version: 1,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["version"], 3);
        let resp = get_master_persona(
            State(state.clone()),
            axum::extract::Query(PersonaQuery {
                delegate: delegate.into(),
            }),
        )
        .await;
        let view = body_json(resp).await;
        assert_eq!(view["current"]["body"], "Be warm and brief.");

        // A rollback to a never-kept version is a loud 404.
        let resp = rollback_master_persona(
            State(state.clone()),
            Json(PersonaRollbackRequest {
                delegate_omni: delegate.into(),
                version: 99,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = delete_master_persona(
            State(state.clone()),
            Json(PersonaQueryBody {
                delegate_omni: delegate.into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["removed"], 3); // v3 current + 2 history
        let resp = get_master_persona(
            State(state),
            axum::extract::Query(PersonaQuery {
                delegate: delegate.into(),
            }),
        )
        .await;
        let view = body_json(resp).await;
        assert!(view["current"].is_null());
    }

    #[tokio::test]
    async fn persona_edit_validation_and_restart_unconfigured_fail_loud() {
        let state = make_state();
        // Edit-time validation → 422 with the guardrail reason.
        let resp = edit_master_persona(
            State(state.clone()),
            Json(PersonaEditRequest {
                delegate_omni: "0xAbCd1234".into(),
                body: "You are AgentKeys itself.".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body_json(resp).await["error"]
            .as_str()
            .unwrap()
            .contains("persona_identity_claim"));
        // A malformed delegate omni is a 400, not a stored garbage key.
        let resp = edit_master_persona(
            State(state.clone()),
            Json(PersonaEditRequest {
                delegate_omni: "not-an-omni".into(),
                body: "fine body".into(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // Restart with no sandbox configured → 503, never a silent no-op.
        let resp = restart_master_agent(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The context VIEW treats unconfigured as a legit absent state.
        let resp = get_master_agent_context(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["configured"], false);
    }
}
