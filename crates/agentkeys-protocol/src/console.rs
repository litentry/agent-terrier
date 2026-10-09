use crate::ContextKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub fn default_stored_version() -> String {
    "v1".to_string()
}

/// One element of the per-namespace JSON array `knowledge:<ns>.enc` (#201 Phase 4).
/// Fixes the lossy single-body overwrite: a namespace with several memories
/// round-trips as one array. The agent reads the same blobs (W4 inheritance
/// defers the agent WRITE path; the inject already renders this shape).
/// `version` + `kind` (#390) are serde-defaulted so pre-#390 blobs decode
/// unchanged (`v1` / `knowledge`); the persona namespace relies on both for
/// its durable version history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredMemoryEntry {
    pub key: String,
    pub title: String,
    pub body: String,
    pub updated: String,
    pub bytes: u64,
    #[serde(default = "default_stored_version")]
    pub version: String,
    #[serde(default)]
    pub kind: ContextKind,
}

/// The `config/memory-taxonomy.enc` object (#178 §7 / #201): the master-only
/// category set the web list resolves WITHOUT decrypting any memory blob. The
/// categories are the namespaces the operator has planted; labels are derived.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemoryTaxonomy {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub categories: Vec<MemoryCategory>,
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
pub const TAXONOMY_SERVICE: &str = "memory-taxonomy";

/// The signed `service` of the Config-class CHANNEL REGISTRY object (→ S3 key
/// `bots/<O_master>/config/channel-registry.enc`) — the master-curated catalog
/// of channel definitions (#404). This is the "registry-from-config-data-class
/// sync" the channel worker crate docs deferred: the worker/broker stay
/// grant-anchored (a channel id is free-form at the chain layer); the registry
/// is the MASTER's bookkeeping — which ids exist, their display names — so the
/// web app can offer selection instead of silent free-text creation, and the
/// daemon can re-name on-chain grant hashes after a restart.
pub const CHANNEL_REGISTRY_SERVICE: &str = "channel-registry";

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
    /// #664 — the channel's endpoint KIND (the closed vocabulary an app slot
    /// binds by: messaging · chat · display · camera · …). Additive; absent on
    /// pre-#664 rows (the wizard then offers the row for any kind).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub kind: Option<crate::ChannelEndpointKind>,
    /// #664 — the endpoint's OWN device actor when it has one (`0x`-omni): the
    /// gateway behind a messaging row, a paired display. An install grants that
    /// actor the feed's mirror direction in the same Touch ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub endpoint_actor_omni: Option<String>,
}

/// The receipt of `POST /v1/channels/clear-orphaned`: `removed` = the registry
/// rows dropped (no actor held a grant on them, by name or on-chain hash),
/// `kept` = the rows still in use, `storage` = the registry's durability flag
/// (`"ok"` durable Config-class doc · `"cached"` dev-only in-memory).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiChannelsClearOrphaned {
    pub removed: Vec<String>,
    pub kept: Vec<String>,
    pub storage: String,
}

/// The durable registry doc (config-class, master-only). Version field for
/// forward evolution; the vec is small (a household's channel count).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelRegistry {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub channels: Vec<ApiChannel>,
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
pub const BINDING_MANIFEST_SERVICE: &str = "binding-manifest";

/// The signed `service` of the Config-class GATEWAY CONTACT REGISTRY object
/// (→ S3 key `bots/<O_master>/config/gateway-contact-registry.enc`) — #424 §2.
/// The durable, master-only copy of the WeChat gateway's contact registry; the
/// gateway-host file stays the working cache. The daemon write-throughs it on
/// every mutating gateway admin proxy and restores it to an EMPTY (rebuilt)
/// gateway on the first contacts read.
pub const GATEWAY_CONTACTS_SERVICE: &str = "gateway-contact-registry";

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
    /// `"device"` (channel endpoint), `"console"` (console device actor), or `"delegate"` (sandbox resident).
    pub kind: String,
    /// The service NAMES the operator actually granted (`channel-pub:<id>`,
    /// `knowledge:<ns>`, `cred:<service>`, …) — the readable twin of the on-chain
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
    /// The delegate's bridge base (`sandbox.agent_url` of the spawn / #577
    /// update response — the veFaaS gateway, routed per instance by header),
    /// so the preset can be re-applied later without a spawn response in
    /// hand. Absent on a row that predates 2026-09-17 until its next update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_url: Option<String>,
    /// #427 — the delegate's `knowledge:<ns>` namespace name (the #425 O2
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
    /// #543 — the spawn ceremony's runtime/metering outcome, persisted so the
    /// #233 reconcile can answer "is this delegate metered / why is its chat
    /// silent" after a daemon restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<ApiRuntimeStatus>,
}

/// The durable manifest doc (config-class, master-only). Small: one entry per
/// bound actor in the household fleet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BindingManifest {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub bindings: Vec<BindingManifestEntry>,
}

/// Bare-hex lowercase form for manifest joins — lowercase FIRST so `0X` strips
/// too (`normalize_omni_0x` only guarantees a prefix, not case).
pub fn manifest_norm(s: &str) -> String {
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
                if entry.agent_url.is_none() {
                    entry.agent_url = existing.agent_url.clone();
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
                if entry.runtime.is_none() {
                    entry.runtime = existing.runtime.clone();
                }
                *existing = entry;
            }
            None => {
                if entry.kind.is_empty() {
                    // A scope commit on an actor the manifest never saw — derive
                    // the kind with the SAME predicate the accept card / D9
                    // spawn gate use (all-channel grants = device).
                    let joined = entry.granted_service_names.join(" ");
                    entry.kind = if crate::scope_is_device_only(&joined) {
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

#[derive(Clone, Debug, Default, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiScopeBits {
    /// `knowledge:<ns>` granted — the delegate may READ the master's shared canonical
    /// memory for this namespace (#295 distribution). The delegate's OWN local
    /// memory is its own and is not represented here.
    pub read: bool,
    /// `proposal:<ns>` granted — the delegate may WRITE/suggest into the master's
    /// absorption inbox for this namespace (#339), which the master curates. A
    /// DISTINCT on-chain grant (`keccak("proposal:<ns>") != keccak("knowledge:<ns>")`), so
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
    /// What this actor IS — `"device"` (channel endpoint, §14.10) or
    /// `"delegate"` (sandbox-resident) — from the binding manifest, which
    /// records it at accept/scope-commit time.
    ///
    /// `None` = genuinely unknown (no manifest entry — e.g. an actor rebuilt
    /// from chain), NOT "delegate". The UI must not guess from the scope: it
    /// used to infer device-ness from "all grants are channel grants", so
    /// revoking a device's grants silently demoted it to a delegate and a real
    /// device showed up under Delegates with its identity unrecognizable. An
    /// actor's TYPE is a property of its binding, never of its current
    /// permissions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope: Option<HashMap<String, ApiScopeBits>>,
    /// #248: on-chain scope service ids (0x-hex keccak) that aren't a known
    /// `knowledge:<ns>` — e.g. `cred:<service>` granted at accept. The panel's
    /// set-replace commit echoes these back so a memory toggle can't wipe them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope_unknown_service_ids: Option<Vec<String>>,
    /// #541: the SUBSET of `scope_unknown_service_ids` this daemon resolved to
    /// `channel-pub:<id>`/`channel-sub:<id>` via the channel registry.
    ///
    /// Why it must be exposed separately: `scope_unknown_service_ids`
    /// deliberately keeps the channel hashes (a MEMORY commit has to echo them
    /// so it cannot wipe channels). But a CHANNEL commit needs the opposite —
    /// blind-echoing them would silently re-add the very grant the operator
    /// just removed. The channel editor computes `preserve = unknown − channel`
    /// and re-sends the channel NAMES it wants, so removal actually takes.
    /// Only the daemon can supply this: the hash→name direction needs keccak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope_channel_service_ids: Option<Vec<String>>,
    /// #614: the SUBSET of `scope_unknown_service_ids` this daemon resolved to a
    /// capability service (`tool:<class>` — enumerable candidates; `plugin:<id>`
    /// names ride the binding-manifest path into `services` instead). Same
    /// preserve semantics as `scope_channel_service_ids` (#541): the hashes stay
    /// in `scope_unknown_service_ids` so a memory commit echoes them, and a
    /// future capability editor subtracts exactly this subset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub scope_capability_service_ids: Option<Vec<String>>,
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
    /// #429 — the delegate's `knowledge:<ns>` namespace name (manifest layer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub memory_ns: Option<String>,
    /// #543 — the delegate's spawn-ceremony runtime/metering outcome (manifest
    /// layer). Absent for devices/masters/pre-#543 spawns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub runtime: Option<ApiRuntimeStatus>,
}

/// #543 — a delegate's spawn-ceremony runtime/metering outcome, persisted in
/// the binding manifest and surfaced as `ApiActor.runtime`. Answers, without
/// broker logs: did the sandbox spawn, and is its LLM path gate-metered?
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiRuntimeStatus {
    /// Gate provisioning outcome: `provisioned` (metered per-delegate relay-key
    /// path) | `not-configured` | `misconfigured` | `failed`. Anything but
    /// `provisioned` means the delegate's LLM turns are UNMETERED (opt-in
    /// stacks) or refused (#543 fail-closed).
    pub gate_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gate_error: Option<String>,
    /// The spawn ceremony's sandbox-ensure error (absent = the runtime spawned
    /// clean) — the "why is this delegate's chat silent" answer (#541 gap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub spawn_error: Option<String>,
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

#[derive(Debug, Serialize)]
pub struct CredService {
    pub service: String,
    pub category: String,
    pub sensitivity: agentkeys_catalog::Sensitivity,
}

#[derive(Debug, Deserialize)]
pub struct StoreCredRequest {
    pub service: String,
    pub secret: String,
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

#[derive(Debug, Deserialize)]
pub struct MemoryEntryQuery {
    pub ns: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    pub ns: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct HistoryVersionQuery {
    pub ns: String,
    pub key: String,
    pub n: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiPersonaState {
    pub delegate_omni: String,
    /// The live persona document (`soul:<omni>`), if one was ever authored.
    pub current: Option<crate::web_api::ApiMemoryEntry>,
    /// Superseded versions, newest first (rollback targets, max 5 kept).
    pub versions: Vec<crate::web_api::ApiMemoryEntry>,
    /// Whether a sandbox bridge is configured (edits apply live vs store-only).
    pub sandbox_configured: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiPersonaEditResponse {
    pub ok: bool,
    pub version: u32,
    pub applied: bool,
    pub apply_detail: String,
}

#[derive(Debug, Deserialize)]
pub struct PersonaQuery {
    pub delegate: String,
}

#[derive(Debug, Deserialize)]
pub struct PersonaEditRequest {
    pub delegate_omni: String,
    pub body: String,
}

#[derive(Debug, Deserialize)]
pub struct PersonaRollbackRequest {
    pub delegate_omni: String,
    pub version: u32,
}

#[derive(Debug, Deserialize)]
pub struct PersonaQueryBody {
    pub delegate_omni: String,
}

#[derive(Debug, Deserialize)]
pub struct ClassifyTagRequest {
    #[serde(default)]
    pub data_class: String,
    pub entity: String,
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

/// `POST /v1/agent/update` body from the web app.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonAgentUpdateRequest {
    pub device_key_hash: String,
    #[serde(default)]
    pub force: bool,
}

/// One delegate's update outcome, typed for the generated TS contract (#215
/// B2 — the frontend never hand-declares a wire interface).
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiAgentUpdateResult {
    pub device_key_hash: String,
    pub old_sandbox_ids: Vec<String>,
    pub sandbox_id: Option<String>,
    pub sandbox_status: Option<String>,
    pub sandbox_error: Option<String>,
    /// Whether the runtime-home hand-off landed in the replacement.
    pub session_migrated: bool,
    /// Always-present human-readable hand-off outcome (what migrated, or why
    /// nothing could — pre-#577 image, unsupported backend, oversized home).
    pub session_detail: String,
}

/// `POST /v1/agent/image-status` body from the web app.
#[derive(Debug, Deserialize)]
pub struct DaemonImageStatusRequest {
    pub device_key_hashes: Vec<String>,
}

/// The fleet image-staleness answer (#577): which delegates run older bits
/// than the current pre-cache registration.
#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiImageStatus {
    pub image: Option<String>,
    pub current_registration_id: Option<String>,
    pub precache_status: Option<String>,
    pub delegates: Vec<ApiDelegateImageStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ApiDelegateImageStatus {
    pub device_key_hash: String,
    pub sandbox_id: Option<String>,
    pub sandbox_status: Option<String>,
    /// The instance's veFaaS lease deadline, verbatim (`null` on backends
    /// without one).
    pub expire_at: Option<String>,
    pub booted_registration_id: Option<String>,
    /// The frozen registration's source image ref — the VERSIONED tag the
    /// instance actually booted (#598 `…:vYYYYMMDD-HHMMSS-g<sha8>`), the
    /// human "which build is this delegate on" answer next to the fleet's
    /// current `image` above.
    pub booted_image_url: Option<String>,
    /// The LIVE agent identity the instance's bridge reports (#577 follow-up):
    /// agent name the bridge reports (`dsh` since #621), its running version (the bump
    /// ground truth), and the LLM endpoint id.
    pub agent_engine: Option<String>,
    pub agent_version: Option<String>,
    pub model: Option<String>,
    /// `true` = stale, `false` = current, `null` = unknowable (no live
    /// instance / app-default image / no registration to compare).
    pub stale: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct InboxCurateRequest {
    pub s3_key: String,
    /// #390 §16.2 — the viewed-body watermark for `skill` proposals: the item's
    /// `content_hash` as returned by `/v1/master/inbox/entry`. A skill accept
    /// WITHOUT a matching hash is rejected (the gate can't prove the master saw
    /// the body). Ignored for `knowledge`; `persona` is never adoptable.
    #[serde(default)]
    pub confirm_content_hash: Option<String>,
    /// D-K5 — when the proposal's key already exists with a different body:
    /// `"replace"` (the entry becomes the proposal) or `"keep-both"` (the
    /// proposal lands under the first free `<key>-N`). Absent = refuse with
    /// 409 `entry_exists` so the console shows the diff first.
    #[serde(default)]
    pub on_conflict: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub kind: Option<crate::ChannelEndpointKind>,
    #[serde(default)]
    pub endpoint_actor_omni: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateChannelRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub kind: Option<crate::ChannelEndpointKind>,
    #[serde(default)]
    pub endpoint_actor_omni: Option<String>,
}

pub fn valid_channel_id(id: &str) -> bool {
    let n = id.len();
    (1..=48).contains(&n)
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}
