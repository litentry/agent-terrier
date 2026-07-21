//! The broker/worker wire protocol — the **single owner** of every request
//! and response shape the cap-mint + worker chain serializes (issue #203).
//!
//! Pure serde, **no transport** (no reqwest/tokio/aws), so it compiles to
//! `wasm32`: the native client `agentkeys-backend-client` re-exports it as
//! `::protocol`, and the browser host `agentkeys-web-core` (wasm) depends on
//! it directly. That split is the parity-ladder rung-3 move for the wire
//! shapes — the browser and the native client share ONE definition and cannot
//! drift (they used to: `ttl_seconds` was a required `u64` in backend-client
//! but `Option<u64>` in web-core's own copy, and web-core's copy was missing
//! the #76 K10 cap-PoP fields entirely). web-core must NOT depend on
//! `agentkeys-backend-client` instead: that crate pulls `aws-sdk-sts` +
//! `tokio` + native `reqwest` via the provisioner and breaks the wasm build
//! (the `wasm32` CI gate in `e2e-ci.yml` enforces this).
//!
//! Before the one-owner discipline the same JSON was hand-typed in three
//! places (the MCP backend, the daemon `ui_bridge`, and bash `jq -n` bodies in
//! the harness), which is the structural cause of the drift bugs #200 fixed
//! (`evm_address` vs `{address,chain_id}`, bare-vs-`0x` omni, per-namespace
//! field shapes). Re-typing one of these in a second place is now either a
//! compile error (Rust callers share these types) or a fixture mismatch (the
//! harness gate diffs bash bodies against `agentkeys-backend-client`'s
//! `fixtures` module).
//!
//! Naming follows arch.md's canonical-names rule: the field names here MUST
//! match what `agentkeys_broker_server::handlers::cap` and the
//! `agentkeys_worker_*` handlers deserialize. We mirror by hand (not a shared
//! struct dep) because the broker/worker are heavy binaries — but the mirror
//! is now in ONE place, exercised end-to-end in the MCP server's
//! `tests/three_acts.rs` and pinned by the backend-client fixtures.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Op discriminator that maps onto the four broker cap-mint endpoints. The
/// route is the source of truth for the cap's `data_class` — the broker
/// statically derives the `DataClass` variant from which endpoint was hit, so
/// a `Memory` cap can never be minted from a `/v1/cap/cred-*` request (issue
/// #90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapMintOp {
    CredStore,
    CredFetch,
    MemoryPut,
    MemoryGet,
    /// #295 P1 — delegated READ of the master's CANONICAL memory (master-hub
    /// distribution). Mints `CapOp::CanonicalFetch`/`DataClass::Memory` at
    /// `/v1/cap/memory-canonical-get`; `op_str` is `"canonical_fetch"` so the
    /// K10 cap-PoP preimage matches the worker's `check_op`. Distinct from
    /// `MemoryGet` (own working memory) — see docs/plan/master-hub-topology.md §6a.
    MemoryCanonicalGet,
    /// #339 P2 — delegated APPEND to the master's absorption INBOX (master-hub
    /// absorption / "push"). Mints `CapOp::Append`/`DataClass::Memory` at
    /// `/v1/cap/memory-append`; `op_str` is `"append"`. The delegate proposes a
    /// learning into `bots/<operator>/inbox/<delegate>/…` (staging, NOT
    /// canonical); the master curates it into canonical later. Gated by a
    /// **distinct** on-chain `inbox:<ns>` grant — NEVER the `memory:<ns>` read
    /// grant (`readOnly` is a dead flag) — see docs/plan/master-hub-topology.md §6b/§8.
    MemoryAppend,
    /// #201 config data class — master-only taxonomy/config object. A third
    /// `DataClass::Config` with its own bucket + IAM role (arch.md §17.2); the
    /// cred + memory workers reject a Config cap via `verify::check_data_class`.
    ConfigStore,
    ConfigFetch,
    /// #406 channels phase 1 — the `channel` data class (`docs/spec/agent-channel-decoupling.md`
    /// D2/D7). PUBLISH an event into a channel feed. Mints `CapOp::ChannelPublish`/
    /// `DataClass::Channel` at `/v1/cap/channel-pub`; `op_str` is `"channel_publish"`.
    /// Direction is carried in the SIGNED op (and the `channel-pub:<id>` service),
    /// so a publish cap can NEVER be redeemed at the subscribe endpoint (D2 — the
    /// direction-denial isolation gate).
    ChannelPublish,
    /// #406 channels phase 1 — SUBSCRIBE (consume) events from a channel feed.
    /// Mints `CapOp::ChannelSubscribe`/`DataClass::Channel` at `/v1/cap/channel-sub`;
    /// `op_str` is `"channel_subscribe"`. Distinct on-chain grant (`channel-sub:<id>`)
    /// from the publish grant — granting one never grants the other.
    ChannelSubscribe,
    /// #441 speech — USE the stack's speech plane (ASR/TTS) through the broker
    /// STS relay. Mints `CapOp::SpeechUse`/`DataClass::Speech` at
    /// `/v1/cap/speech` (service statically `"speech"` — the on-chain grant
    /// id); redeemed ONLY at the broker's `/v1/cap/speech-sts` for short-TTL
    /// Transcribe/Polly-only AWS creds. No bucket, no worker.
    SpeechUse,
}

impl CapMintOp {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cred_store" => Some(Self::CredStore),
            "cred_fetch" => Some(Self::CredFetch),
            "memory_put" => Some(Self::MemoryPut),
            "memory_get" => Some(Self::MemoryGet),
            "memory_canonical_get" => Some(Self::MemoryCanonicalGet),
            "memory_append" => Some(Self::MemoryAppend),
            "config_store" => Some(Self::ConfigStore),
            "config_fetch" => Some(Self::ConfigFetch),
            "channel_publish" => Some(Self::ChannelPublish),
            "channel_subscribe" => Some(Self::ChannelSubscribe),
            "speech_use" => Some(Self::SpeechUse),
            _ => None,
        }
    }

    pub fn broker_path(self) -> &'static str {
        match self {
            Self::CredStore => "/v1/cap/cred-store",
            Self::CredFetch => "/v1/cap/cred-fetch",
            Self::MemoryPut => "/v1/cap/memory-put",
            Self::MemoryGet => "/v1/cap/memory-get",
            Self::MemoryCanonicalGet => "/v1/cap/memory-canonical-get",
            Self::MemoryAppend => "/v1/cap/memory-append",
            Self::ConfigStore => "/v1/cap/config-store",
            Self::ConfigFetch => "/v1/cap/config-fetch",
            Self::ChannelPublish => "/v1/cap/channel-pub",
            Self::ChannelSubscribe => "/v1/cap/channel-sub",
            Self::SpeechUse => "/v1/cap/speech",
        }
    }

    pub fn data_class(self) -> &'static str {
        match self {
            Self::CredStore | Self::CredFetch => "credentials",
            Self::MemoryPut | Self::MemoryGet | Self::MemoryCanonicalGet | Self::MemoryAppend => {
                "memory"
            }
            Self::ConfigStore | Self::ConfigFetch => "config",
            Self::ChannelPublish | Self::ChannelSubscribe => "channel",
            Self::SpeechUse => "speech",
        }
    }

    /// The signed-cap `CapOp` snake_case string this endpoint mints — the value
    /// that lands in `CapPayload.op` and must match the K10 cap-PoP preimage
    /// (issue #76). Store-class endpoints → `"store"`, fetch-class → `"fetch"`.
    /// Callers building the cap-PoP signature MUST use this so the worker's
    /// recomputed preimage agrees byte-for-byte.
    pub fn op_str(self) -> &'static str {
        match self {
            Self::CredStore | Self::MemoryPut | Self::ConfigStore => "store",
            Self::CredFetch | Self::MemoryGet | Self::ConfigFetch => "fetch",
            // #295 P1 — must match agentkeys_worker_creds::verify::CapOp::CanonicalFetch
            // (and the broker's) so the K10 cap-PoP preimage agrees byte-for-byte.
            Self::MemoryCanonicalGet => "canonical_fetch",
            // #339 P2 — must match agentkeys_worker_creds::verify::CapOp::Append
            // (and the broker's) so the K10 cap-PoP preimage agrees byte-for-byte.
            Self::MemoryAppend => "append",
            // #406 — must match agentkeys_worker_creds::verify::CapOp::ChannelPublish/
            // ChannelSubscribe (and the broker's) so the K10 cap-PoP preimage agrees
            // byte-for-byte. Direction is the signed op — a publish cap and a subscribe
            // cap recover to DIFFERENT preimages even for the same channel.
            Self::ChannelPublish => "channel_publish",
            Self::ChannelSubscribe => "channel_subscribe",
            // #441 — must match the broker's CapOp::SpeechUse and the worker
            // mirror so the K10 cap-PoP preimage agrees byte-for-byte.
            Self::SpeechUse => "speech_use",
        }
    }
}

/// The cap-mint request as the *caller* constructs it (omni's, service,
/// device hash, TTL). [`BrokerCapRequest`] is the on-the-wire serialization;
/// they have the same fields today but stay distinct so a caller-side concept
/// (e.g. a future client-only field) can't silently leak onto the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapMintRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    pub ttl_seconds: u64,
}

/// A device→sandbox delegation (issue #369), carried alongside the cap-mint PoP
/// when `client_sig` was produced by a sandbox's OWN ephemeral key rather than the
/// device K10 directly. The **device** (not the broker) signs `delegation_sig`
/// over `agentkeys_device_core::delegation_payload(device_key_hash, sandbox_key,
/// scope, expires_at)`, so a compromised broker cannot forge it; the WORKER
/// re-verifies it independently (`agentkeys_core::device_crypto::verify_delegation`)
/// before any S3 touch. This is the single owner of the delegation wire shape —
/// the broker echoes it into the minted cap-token and the worker deserializes the
/// SAME type, so the two cannot drift (#203).
///
/// `sandbox_key` is deliberately NOT carried: it is the recovered cap-PoP signer,
/// which binds the delegation to exactly the key that signed THIS cap (a
/// delegation for key A cannot redeem a cap signed by key B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPath {
    /// Canonical scope the delegation is bounded to — space-delimited `data_class`
    /// or `data_class:op` tokens (e.g. `"memory credentials:fetch"`). Carried in
    /// cleartext (the worker needs it to rebuild the preimage + apply its policy)
    /// but integrity-protected by `delegation_sig`.
    pub scope: String,
    /// Unix-seconds expiry — the device-signed TTL bound. The worker enforces
    /// `now < expires_at` (the device-core crate is clock-free).
    pub expires_at: u64,
    /// The device's EIP-191 signature over the delegation preimage.
    pub delegation_sig: String,
}

/// Broker cap-mint request body — the exact JSON
/// `agentkeys_broker_server::handlers::cap` deserializes for all `/v1/cap/*`
/// endpoints, AND the on-the-wire shape the browser host
/// (`agentkeys-web-core`) serializes directly (it has no separate caller-side
/// type — it aliases this as `CapRequest`).
///
/// Carries the K10 cap-mint **proof-of-possession** (issue #76):
/// `client_sig` is an EIP-191 signature by the caller's K10 device key over
/// `device_crypto::cap_pop_payload(operator, actor, service, op, data_class,
/// client_nonce, client_ts)`. The broker validates it and the WORKER re-verifies
/// it independently — so a compromised broker (which lacks the K10 private key)
/// cannot mint a usable cap. Built by `BackendClient::cap_mint` (in
/// `agentkeys-backend-client`) from an injected `DeviceKey`, NOT hand-set by
/// callers.
///
/// `ttl_seconds` is `Option` + `skip_serializing_if` to mirror the broker's
/// `#[serde(default = "default_ttl_seconds")]`: `None` omits the field so the
/// broker applies its default (300s, clamped 60..1800); native callers coming
/// from [`CapMintRequest`] always send `Some(..)` (wire-identical to before).
/// This is the SINGLE on-wire definition, so the browser and the native client
/// can no longer drift on it — previously each crate had its own copy and they
/// diverged on this very field (the bug class #203 closed for the chain, now
/// extended to the browser).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerCapRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub service: String,
    pub device_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    // The K10 cap-PoP is OPTIONAL on the wire (issue #76 staged rollout): a caller
    // that holds the actor's K10 signs (the broker validates + the worker
    // re-verifies); a caller without one (e.g. a master before its K10 is
    // registered) omits these. Enforcement (reject-if-absent) is opt-in via the
    // worker's AGENTKEYS_WORKER_REQUIRE_CAP_POP — until then the PoP is
    // verified-when-present. `skip_serializing_if` keeps the no-PoP body
    // byte-identical to the pre-#76 shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<u64>,
    /// Device→sandbox delegation (issue #369) — present only when `client_sig` was
    /// produced by a sandbox's ephemeral key rather than the device K10 directly.
    /// `skip_serializing_if` keeps the no-delegation body byte-identical to the
    /// pre-#369 shape (so the #203 cap-mint fixture is unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_path: Option<DelegationPath>,
}

/// Opaque cap-token blob — the broker signs it and the worker verifies the
/// signature; this side never inspects the inside, so a JSON `Value` is the
/// right type.
pub type CapToken = Value;

// ── memory worker (`/v1/memory/{put,get}`) ──────────────────────────────────

/// Memory-worker `/v1/memory/put` request body. Mirrors
/// `agentkeys_worker_memory::handlers::PutRequest`. `namespace` rides at the
/// body level for Phase 1 (lifting it into a SIGNED CapPayload field is an M4
/// follow-up per the wire-real-paths plan §8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
    pub namespace: String,
}

/// Memory-worker `/v1/memory/get` request body. Mirrors
/// `agentkeys_worker_memory::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetBody {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryPutResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryGetResp {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── config worker (`/v1/config/{put,get}`) — #201 config data class ──────────

/// Config-worker `/v1/config/put` request body. Mirrors
/// `agentkeys_worker_config::handlers::PutRequest`. Config is a single
/// master-only object (the memory-types taxonomy), so — unlike `MemoryPutBody`
/// — there is NO `namespace` field; the object's identity is the signed cap
/// `service` (`memory-taxonomy`).
///
/// EXACTLY ONE of `envelope_b64` / `plaintext_b64` (#372 item 2 / #91):
/// - `envelope_b64` — the v3 path: a client-encrypted envelope (signer-derived
///   per-actor KEK, `agentkeys-core::kek`) the worker stores VERBATIM; the
///   worker never sees plaintext or any key that opens it.
/// - `plaintext_b64` — the legacy stage-1 path: the worker encrypts under its
///   static env KEK. Deprecated; rejected once the worker runs
///   `AGENTKEYS_CONFIG_REQUIRE_V3=1`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPutBody {
    pub cap: CapToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_b64: Option<String>,
}

/// Config-worker `/v1/config/get` request body. Mirrors
/// `agentkeys_worker_config::handlers::GetRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigGetBody {
    pub cap: CapToken,
}

/// EXACTLY ONE of `envelope_b64` / `plaintext_b64` is set (#372 item 2):
/// v3 blobs come back as the raw envelope for CLIENT-side decrypt under the
/// signer-derived KEK; legacy v2 blobs come back worker-decrypted.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigGetResp {
    pub ok: bool,
    #[serde(default)]
    pub plaintext_b64: Option<String>,
    #[serde(default)]
    pub envelope_b64: Option<String>,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── channel worker (`/v1/channel/{publish,poll,teardown}`) — #406 channels ───
//
// The `channel` data class (`docs/spec/agent-channel-decoupling.md` D7): a
// durable, envelope-encrypted feed under the per-data-class `$CHANNEL_BUCKET`,
// with the NRT decision (§14.12) — the channel worker is the ONLY write path,
// so it completes held consumer long-polls in-process the instant an event
// lands (write-through wakeup). S3/TOS is the durable record, never the
// notification path. Feed-backed (async) kinds only; `session`-kind channels
// are direct-transport and carry no feed.

/// The transport shape of a channel (#408 §4/D1). **Feed-backed** channels are
/// async + durable (camera → doorkeeper, weixin, UI feeds): the channel worker's
/// S3 feed + the §14.12 NRT long-poll. **Session** channels stream direct to a
/// live adapter endpoint (the console's chat to its delegate's sandbox bridge) —
/// grant-gated the SAME (`channel-pub/sub:<id>` caps), but with **no durable
/// feed** (latency). A `session` channel is the phase-3 replacement for the
/// legacy #369 device→sandbox delegation for NEW device↔delegate binds. Wire
/// spelling lowercase; absent = `feed_backed` (every pre-#408 channel is a feed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    #[default]
    FeedBacked,
    Session,
}

impl ChannelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelKind::FeedBacked => "feed_backed",
            ChannelKind::Session => "session",
        }
    }

    /// Whether this kind persists events in a durable feed. `session` channels are
    /// direct-transport (no feed) — a poll/subscribe against a session channel has
    /// nothing to read; delivery is the live bridge.
    pub fn has_feed(&self) -> bool {
        matches!(self, ChannelKind::FeedBacked)
    }
}

/// The direction an event flows relative to a keyed actor's grant. Carried on
/// [`ChannelEvent`] for the subscriber's provenance display; the AUTHORIZATION
/// direction is the SIGNED cap op (publish vs subscribe), never this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelDirection {
    /// Toward the agent (contact/device → agent) — the inbound feed.
    In,
    /// Away from the agent (agent → contact/device) — the outbound feed.
    Out,
}

/// The producer of a [`ChannelEvent`] — EXACTLY ONE of a keyed actor XOR an
/// externally-authenticated contact (`docs/spec/agent-channel-decoupling.md`
/// §4.1). **Stamped by the worker/adapter, NEVER self-attributed by the
/// payload** (the absorption-inbox provenance rule): the channel worker sets
/// `Actor` from the cap-signed `actor_omni`; the gateway sets `Contact` from
/// the transport-verified identity. A delegate can label an event's `kind`,
/// never its `producer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelProducer {
    /// A keyed actor (delegate or device) — the `0x`-omni the cap was signed by.
    Actor { actor_omni: String },
    /// An externally-authenticated, keyless contact (the family), verified at
    /// the gateway. `contact_id` is the registry id; `tier` is the household
    /// tier (D5). No keys, no omni — the transport authenticated them.
    Contact { contact_id: String, tier: String },
}

/// The payload kind of a [`ChannelEvent`]. Continuous media (realtime
/// speech/video) is deliberately NOT here — it stays on the §22d.3a gate path;
/// channels carry text, commands, docs, discrete frames, and `audio-clip`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChannelEventKind {
    Text,
    Image,
    AudioClip,
    Frame,
    Command,
    Doc,
}

/// #519/#522 — declared audio parameters riding an `audio-clip` turn. All
/// optional + additive (absent = consumer defaults), producer-declared like
/// `kind`: the device states which reply voice/rate it wants and what
/// container its clip is in (replacing consumer magic-byte sniffing).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAudioParams {
    /// Doubao speaker id the REPLY should be synthesized with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    /// Doubao 语速 for the reply, [-50, 100] (consumer clamps).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speech_rate: Option<i32>,
    /// The PAYLOAD clip's own container (wav/mp3/ogg).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// The one canonical channel event envelope (`docs/spec/agent-channel-decoupling.md`
/// §4.1). This is the DECRYPTED shape the worker stores inside the standard
/// envelope and hands back to authorized subscribers; `producer` is
/// worker/gateway-stamped. `body` carries small inline payloads (text/command);
/// `body_ref` is an S3 key into the feed for large payloads (frames/docs) —
/// exactly one is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEvent {
    /// Worker-assigned unique id (also the tail of the feed S3 key), so a
    /// subscriber can dedup and a producer cannot forge ordering.
    pub event_id: String,
    pub channel_id: String,
    pub direction: ChannelDirection,
    /// Worker/gateway-stamped — never a payload-supplied field (§4.1).
    pub producer: ChannelProducer,
    pub kind: ChannelEventKind,
    /// Inline payload (base64) for small kinds. Exactly one of `body`/`body_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// S3 key into the feed for large payloads. Exactly one of `body`/`body_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<String>,
    /// Worker-stamped unix-millis — the feed ordering key + poll cursor source.
    pub ts_millis: u64,
    /// Optional conversation/turn correlation id (a reply threads to a prompt).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    /// #522 — audio params for `audio-clip` turns (voice/rate/format).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<ChannelAudioParams>,
}

/// Broker `POST /v1/cap/channel-sts` response (#541) — short-lived, owner-scoped
/// storage credentials the CHANNEL WORKER redeems from the cap it just verified.
/// One definition shared by the broker (producer) and the channel worker
/// (consumer) so the internal mint contract cannot drift (#203 discipline).
/// Deliberately NOT the memory/config client-relay shape: a channel is a shared
/// owner-owned feed, so the participant has nothing of its own to relay and must
/// never hold the owner's storage credential — only the worker redeems these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelStsCreds {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// Unix seconds the credentials expire; the worker caches until ~60 s before.
    pub expiration: i64,
}

/// Channel-worker `POST /v1/channel/publish` request body. The publish cap
/// (`service = channel-pub:<id>`, SIGNED) authorizes the write; the worker
/// stamps `producer`/`event_id`/`ts_millis` and appends the envelope-encrypted
/// event to the feed, completing any held consumer long-poll in-process.
/// `kind`/`direction`/`body`/`correlation` are the producer's declared content;
/// `producer` is NEVER accepted from the body (worker-stamped from the cap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPublishBody {
    pub cap: CapToken,
    pub kind: ChannelEventKind,
    #[serde(default = "channel_direction_in")]
    pub direction: ChannelDirection,
    /// Inline base64 payload for small kinds (exactly one of body/body_ref).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    /// #522 — producer-declared audio params, copied verbatim onto the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<ChannelAudioParams>,
}

fn channel_direction_in() -> ChannelDirection {
    ChannelDirection::In
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelPublishResp {
    pub ok: bool,
    /// The worker-assigned event id (feed key tail).
    pub event_id: String,
    /// The feed S3 key the encrypted event landed at (the durable record).
    pub s3_key: String,
    /// Durable-audit receipt (#229) — see [`MemoryPutResp::audit_envelope_hash`].
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

/// Channel-worker `POST /v1/channel/poll` request body — the NRT long-poll
/// (§14.12). The subscribe cap (`service = channel-sub:<id>`, SIGNED) authorizes
/// the read. Returns every event whose feed key sorts AFTER `after` (the cursor
/// = the last `s3_key`/`event_id` seen, empty = from the start); if none are
/// pending, the worker HOLDS the request up to `wait_seconds`, completing it the
/// instant a matching publish lands (write-through wakeup), else returns empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPollBody {
    pub cap: CapToken,
    /// Cursor: return events strictly after this feed key. Empty = from start.
    #[serde(default)]
    pub after: String,
    /// Max seconds to hold the connection when no event is immediately
    /// available (0 = return immediately; worker clamps to its ceiling).
    #[serde(default)]
    pub wait_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelPollResp {
    pub ok: bool,
    /// Events after the cursor, oldest-first (each `body` is base64 plaintext).
    pub events: Vec<ChannelEvent>,
    /// The new cursor to pass as `after` on the next poll (the last event's
    /// feed key, or the request's `after` unchanged when `events` is empty).
    pub cursor: String,
    /// Durable-audit receipt (#229) for the subscribe read.
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

/// Channel-worker `POST /v1/channel/teardown` — GC a channel's whole feed
/// (master-self / owner-scoped). Mirrors the config/memory teardown shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelTeardownBody {
    pub cap: CapToken,
    pub channel_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelTeardownResp {
    pub ok: bool,
    pub keys_deleted: usize,
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── gateway + contacts (#407 phase 2) — the WeChat gateway PEP ────────────────
//
// A `gateway` is the capability boundary between externally-authenticated
// humans (`contact`s — the family) and agents (`docs/spec/agent-channel-decoupling.md`
// D4/D5/§7). It custodies the ONE scarce transport credential (a WeChat bot per
// KYC'd account — the #384 custody pattern, never in any agent env),
// authenticates each contact via the transport identity (weixin openid),
// enforces L3 audience policy BEFORE anything reaches an agent, and routes.
// **A PEP, never an authority** — grants stay master-signed + chain-verified; a
// contact holds NO keys and NO caps (`ChannelProducer::Contact`, §4.1).

/// A household tier from the D5 template. Tiers are the master-editable POLICY
/// vocabulary (not wire-frozen — the master may add household-specific tiers),
/// but the template six are the defaults the bind ceremony proposes among.
/// Serialized lowercase; unknown wire values are rejected so a typo can't
/// silently create a phantom tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
#[serde(rename_all = "lowercase")]
pub enum ContactTier {
    Owner,
    Partner,
    Elder,
    Kid,
    Helper,
    Guest,
}

impl ContactTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            ContactTier::Owner => "owner",
            ContactTier::Partner => "partner",
            ContactTier::Elder => "elder",
            ContactTier::Kid => "kid",
            ContactTier::Helper => "helper",
            ContactTier::Guest => "guest",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(ContactTier::Owner),
            "partner" => Some(ContactTier::Partner),
            "elder" => Some(ContactTier::Elder),
            "kid" => Some(ContactTier::Kid),
            "helper" => Some(ContactTier::Helper),
            "guest" => Some(ContactTier::Guest),
            _ => None,
        }
    }

    /// The full household template, in descending trust order.
    pub fn household_template() -> [ContactTier; 6] {
        [
            ContactTier::Owner,
            ContactTier::Partner,
            ContactTier::Elder,
            ContactTier::Kid,
            ContactTier::Helper,
            ContactTier::Guest,
        ]
    }

    /// Whether this tier may EVER be proposed operator-grade reach. Operator-grade
    /// data (spend stats, audit) requires operator-grade auth (a session/K11),
    /// NEVER a matching openid alone (L3 rule, §5) — so even `owner` gets the
    /// parent-control deep-link, not the data, over the gateway. This flag is the
    /// gateway's coarse guard that a NON-owner tier can't be granted an
    /// operator-grade alias in its reach.
    pub fn may_hold_operator_grade_reach(&self) -> bool {
        matches!(self, ContactTier::Owner)
    }
}

/// An externally-authenticated, KEYLESS principal in the master-curated registry
/// (D5). The transport authenticates the human (weixin openid today); the master
/// maps + tiers them. NEVER an actor: no omni, no keys, no caps; no feed-history
/// visibility (D13). `reach` is the per-agent `/alias` allowlist this contact may
/// address (e.g. `["chef", "storyteller"]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub contact_id: String,
    /// The transport this identity is authenticated on (`"weixin"` today).
    pub transport: String,
    /// The transport-native id — the weixin openid. The gateway authenticates on
    /// this; it never leaves the gateway/registry (contacts are addressed by
    /// `contact_id` everywhere else).
    pub transport_id: String,
    pub display_name: String,
    pub tier: ContactTier,
    /// The agents (by `/alias`) this contact may reach. Empty = reaches nothing
    /// until the master grants reach (a `guest` default).
    #[serde(default)]
    pub reach: Vec<String>,
}

/// The master-curated contact registry (a `policy`/`config`-data-class document,
/// §14.5 — master-authored, gateway-read; agents see only the worker-stamped
/// `(contact_id, tier)` on events, never the registry). `bound` are live
/// contacts; `pending` are openids that sent a bind code but await master
/// approval (the bind ceremony, §7.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactRegistry {
    #[serde(default)]
    pub bound: Vec<Contact>,
    #[serde(default)]
    pub pending: Vec<PendingBind>,
    /// Master-minted OPEN invites (#418 bind ceremony) — not yet echoed to the
    /// bot. `default` keeps pre-#418 registry files parseable unchanged.
    #[serde(default)]
    pub invites: Vec<BindInvite>,
}

impl ContactRegistry {
    /// Resolve a transport identity (openid) to a BOUND contact. Unknown ids
    /// return `None` — the gateway DROPS them (never reaches an agent).
    pub fn resolve(&self, transport: &str, transport_id: &str) -> Option<&Contact> {
        self.bound
            .iter()
            .find(|c| c.transport == transport && c.transport_id == transport_id)
    }
}

/// An openid that sent a valid bind code and awaits the master's tier+reach
/// confirmation. The small model PROPOSES `proposal`; the registry gains a
/// `Contact` ONLY when the master confirms (advisory-only, D10 — no registry
/// write without the master-confirm call).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingBind {
    pub transport: String,
    pub transport_id: String,
    /// The one-time bind code the master issued + the human echoed to the bot.
    pub bind_code: String,
    /// The model's ADVISORY proposal (never authoritative). `None` until the
    /// tier-proposer runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<TierProposal>,
}

/// The tiny-model's ADVISORY tier+reach proposal for a pending bind (D5/D10).
/// The master confirms every assignment; the confirm card shows the proposed
/// `reach` diff (§9 threat 7 — the confirm must show reach, not just the tier
/// name). This is data the master reviews, NEVER an authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierProposal {
    pub tier: ContactTier,
    pub reach: Vec<String>,
    /// One-line human-readable rationale (from the invite context) — shown on
    /// the master's confirm card.
    pub rationale: String,
}

/// The D13-safe view of a contact for the operator's parent-control surface
/// (#410). The operator has global visibility, but even the operator's view
/// carries **no transport_id (openid)** and **no history** — those never leave
/// the gateway/registry. This is `(contact_id, display_name, tier, reach)` only:
/// the routing policy the operator manages, not the third-party PII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ContactSummary {
    pub contact_id: String,
    pub display_name: String,
    pub tier: ContactTier,
    pub reach: Vec<String>,
}

impl From<&Contact> for ContactSummary {
    fn from(c: &Contact) -> Self {
        ContactSummary {
            contact_id: c.contact_id.clone(),
            display_name: c.display_name.clone(),
            tier: c.tier,
            reach: c.reach.clone(),
        }
    }
}

// ── gateway admin surface (#418) — operator-driven login + bind ceremony ─────
//
// The parent-control app drives the gateway THROUGH the daemon proxy
// (`/v1/master/gateway/*` → the gateway's admin-bearer-gated `/v1/gateway/admin/*`).
// These are the ONE-owner wire shapes for that surface (ts-rs-exported so the
// React app compiles against them — a rename here is a frontend compile error).

/// An OPEN bind invite the master minted (parent-control "邀请家人"). Registry-
/// resident until an unknown sender echoes `bind_code` to the bot (→ a
/// `PendingBind` claims it) and the master approves (→ a bound `Contact`).
/// The invite carries the master's INTENDED identity/tier/reach — the model
/// proposal (D10) may suggest, the master's invite + confirm decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindInvite {
    /// One-time short code the family member sends to the bot (e.g. `AK-7Q2M9X`).
    pub bind_code: String,
    pub contact_id: String,
    pub display_name: String,
    pub tier: ContactTier,
    #[serde(default)]
    pub reach: Vec<String>,
}

/// `GET /v1/gateway/admin/status` — the parent-control gateway card.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayStatusView {
    pub ok: bool,
    /// `oa` | `ilink`.
    pub transport: String,
    /// iLink: a bot token is loaded and the inbound loop is running.
    pub online: bool,
    /// The bound bot id (`…@im.bot`), when known (set by the login ceremony).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_id: Option<String>,
    pub bound_contacts: u32,
    /// Open invites not yet echoed to the bot.
    pub open_invites: u32,
    /// Claimed binds awaiting the master's approve.
    pub pending_binds: u32,
    /// Millis of the iLink loop's last successful poll (`null` = never / OA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub ilink_last_ok_ms: Option<u64>,
    /// True when the TAMPER-PROOF on-chain audit is armed — the audit worker is
    /// wired AND the operator omni is valid 32-byte hex (#419). False means
    /// contact bind/reject/revoke are recorded in the local activity log but NOT
    /// anchored on-chain; the operator must set AGENTKEYS_WEIXIN_OPERATOR_OMNI.
    /// (Surfaced so the skip is LOUD, never a silent drop.)
    #[serde(default)]
    pub audit_on_chain: bool,
}

/// `POST /v1/gateway/admin/login/start` request (#502, plan T9 first step).
/// `operator_omni` is filled SERVER-SIDE by the daemon from the master session
/// — the browser sends an empty body and NEVER supplies it, so this shape is
/// deliberately NOT ts-exported. The gateway records it at `connected` (the
/// tenant identity arrives from the authenticated session, not an env stamp);
/// absent (old daemon / CLI ceremony) keeps the env-stamp behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayLoginStartRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_omni: Option<String>,
}

/// `POST /v1/gateway/admin/login/start` response — render `qrcode_url` as a QR
/// in parent-control; the operator scans it with the SPARE personal-WeChat
/// account (never a family member's daily account — that account BECOMES the bot).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayLoginStartResponse {
    pub ok: bool,
    pub login_id: String,
    pub qrcode_url: String,
}

/// `GET /v1/gateway/admin/login/status?login_id=` response. `status` ∈
/// `wait | scaned | need_verifycode | verify_code_blocked | expired |
/// already_bound | connected | failed`. One call = one server-held poll step
/// (up to ~35 s), so the app just loops until a terminal status.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayLoginStatusResponse {
    pub ok: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_id: Option<String>,
    /// The scanning account's ilink user id (informational provenance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `POST /v1/gateway/admin/login/verify` — the phone showed a pairing number;
/// the operator types it in parent-control and the next status poll carries it.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayLoginVerifyRequest {
    pub login_id: String,
    pub verify_code: String,
}

/// `POST /v1/gateway/admin/bind/invite` — mint a bind invite for a family member.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayBindInviteRequest {
    pub contact_id: String,
    pub display_name: String,
    pub tier: ContactTier,
    #[serde(default)]
    pub reach: Vec<String>,
}

/// The minted invite. `send_text` is the exact message the family member sends
/// to the bot (parent-control renders it as a QR + copyable text).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayBindInviteResponse {
    pub ok: bool,
    pub bind_code: String,
    pub send_text: String,
}

/// `GET /v1/gateway/admin/bind/pending` — the master's approve queue, D13-SAFE:
/// keyed by `bind_code`, NEVER carrying the claiming openid.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayPendingBindView {
    pub bind_code: String,
    pub contact_id: String,
    pub display_name: String,
    pub tier: ContactTier,
    pub reach: Vec<String>,
    /// True once an unknown sender echoed the code (an openid is attached
    /// gateway-side); only a CLAIMED invite can be approved.
    pub claimed: bool,
}

/// `POST /v1/gateway/admin/bind/approve` — the master's confirm (D5: the master
/// CONFIRMS every bind; tier/reach here override the invite's when set).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayApproveRequest {
    pub bind_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<ContactTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<Vec<String>>,
}

/// Approve response — the now-bound contact (D13-safe summary).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayApproveResponse {
    pub ok: bool,
    pub contact: ContactSummary,
}

/// `POST /v1/gateway/admin/contacts/update` — the operator edits a BOUND
/// contact's routing policy (#3 parent-control). Fields left `None` are
/// unchanged; a tier that may not hold operator-grade reach is rejected if the
/// (new) reach still names an operator-grade alias.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayContactUpdateRequest {
    pub contact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<ContactTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reach: Option<Vec<String>>,
}

/// `POST /v1/gateway/admin/contacts/revoke` — the operator UNBINDS a contact;
/// they can no longer reach any agent through the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayContactRevokeRequest {
    pub contact_id: String,
}

/// `POST /v1/gateway/admin/bind/reject` — the master WITHDRAWS an invite (open
/// or claimed) before it binds: the code dies immediately; a claimed sender gets
/// silence from then on. The remove half of the D5 approve gate.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayBindRejectRequest {
    pub bind_code: String,
}

/// `GET /v1/gateway/admin/contacts` (proxied as `/v1/master/gateway/contacts`) —
/// the typed contacts-view envelope (#410's endpoint, now a one-owner shape).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayContactsResponse {
    pub ok: bool,
    pub contacts: Vec<ContactSummary>,
}

/// One line in the operator's LIVE message monitor (#1) — a single inbound turn
/// and the L3 decision it produced. D13-safe: the SENDER is the resolved bound
/// contact's `display_name` (or `"unknown"` for an unbound sender), NEVER the
/// openid; `text` is a short truncated preview for the operator's household view.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayMonitorEvent {
    #[ts(type = "number")]
    pub seq: u64,
    #[ts(type = "number")]
    pub ts_ms: u64,
    pub contact: String,
    pub tier: String,
    pub text: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub target: Option<String>,
}

/// `GET /v1/gateway/admin/monitor?after=<cursor>` — the poll response. `events`
/// are those with `seq >= after`; poll again with `after = cursor`.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayMonitorResponse {
    pub ok: bool,
    #[ts(type = "number")]
    pub cursor: u64,
    pub events: Vec<GatewayMonitorEvent>,
}

/// `GET /v1/gateway/admin/history?before=<ts_ms>&limit=<n>` — the owner's DURABLE
/// message history (#419), newest-first, backward-paginated. Same D13-safe event
/// shape as the live monitor, but read from the append-only log so it survives
/// restarts. Page older by re-requesting with `before = next_before_ts`.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayHistoryResponse {
    pub ok: bool,
    pub events: Vec<GatewayMonitorEvent>,
    /// Oldest `ts_ms` in `events` — the next `before` to page older. Absent when
    /// the page is empty (no older turns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub next_before_ts: Option<u64>,
}

/// One CONTROL-plane action on the gateway (#419) — the operator-facing audit
/// trail of contact management, distinct from message turns (`GatewayMonitorEvent`)
/// and durable (append-only log, survives restarts, unlike the daemon's ephemeral
/// in-memory audit buffer). D13-safe: `contact` is the display_name, never an openid.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayActivityEvent {
    #[ts(type = "number")]
    pub ts_ms: u64,
    /// `invite` | `claim` | `bound` | `rejected` | `revoked` | `connected` | `disconnected`.
    pub action: String,
    /// The contact's display_name (or `—` for a gateway-level action).
    pub contact: String,
    /// Human-readable specifics (tier · reach count, the 6-digit code, the bot id…).
    pub detail: String,
    /// True when this action was ALSO anchored on-chain (operator omni armed).
    pub on_chain: bool,
}

/// `GET /v1/gateway/admin/activity?before=<ts_ms>&limit=<n>` — the durable
/// control-action audit trail, newest-first, backward-paginated.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct GatewayActivityResponse {
    pub ok: bool,
    pub events: Vec<GatewayActivityEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub next_before_ts: Option<u64>,
}

/// A normalized inbound message the gateway builds from a verified transport
/// callback (the transport-specific parsing lives in each gateway worker; this
/// is the canonical shape the L3/routing logic consumes). `alias` is the
/// `/alias` deterministic-routing target when the message starts with one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayInbound {
    pub transport: String,
    pub transport_id: String,
    /// The message text with any leading `/alias ` stripped into `alias`.
    pub text: String,
    /// The `/alias` routing target, if the message began with `/<alias> `.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// The L3 audience decision — may THIS contact reach THAT agent through this
/// gateway, and at what grain (§5 L3). Computed BEFORE anything reaches an agent.
/// `operator_grade_deeplink` is set when the contact asked for operator-grade
/// data (spend stats/audit): the answer is the parent-control deep-link, never
/// the data over the gateway (the L3 rule that operator-grade needs operator-grade
/// auth).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L3Decision {
    pub allowed: bool,
    /// The routed agent alias when `allowed` (deterministic `/alias` only in
    /// phase 2; the advisory router is phase 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_alias: Option<String>,
    /// A stable reason code for audit + the (never-in-channel, D13) parent-control
    /// view: `ok` / `unknown_contact` / `out_of_reach` / `rate_limited` /
    /// `operator_grade_requires_session` / `no_alias`.
    pub reason: String,
    /// Set when the ask was operator-grade — the parent-control deep-link the
    /// contact gets instead of the data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_grade_deeplink: Option<String>,
    /// #410 — how the target was chosen: absent = deterministic `/alias`;
    /// `"advisory_router"` = the tiny-model/keyword router picked it (D10 — the
    /// router is ADVISORY, so this is worker-stamped routing metadata for the
    /// parent-control view; it NEVER widened authority, the pick is always within
    /// the contact's reach).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routed_by: Option<String>,
}

// ── cred worker (`/v1/cred/fetch`) — #216 agent-side vaulted-key fetch ────────

/// Cred-worker `/v1/cred/fetch` request body. Mirrors
/// `agentkeys_worker_creds::handlers::FetchRequest` — just the signed cap; the
/// credential `service` rides INSIDE the cap payload (it can't be spoofed at the
/// body level). The worker S3-GETs `bots/<actor>/credentials/<service>.enc`,
/// decrypts (K3 KEK), and returns the plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchBody {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredFetchResp {
    pub ok: bool,
    pub plaintext_b64: String,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

/// Cred-worker `/v1/cred/store` request body. Mirrors
/// `agentkeys_worker_creds::handlers::StoreRequest` — the signed cap (the
/// credential `service` rides INSIDE the cap payload) plus the base64 plaintext.
/// The worker encrypts (K3 KEK) + S3-PUTs `bots/<actor>/credentials/<service>.enc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreBody {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CredStoreResp {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    /// Durable-audit receipt (#229): the `AuditEnvelope` hash the worker
    /// emitted for this op (`null`/absent on pre-#229 workers or when the
    /// emit failed in best-effort mode).
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

// ── audit worker (`/v1/audit/append/v2`) ────────────────────────────────────

/// Audit envelope version, pinned to `agentkeys_core::audit::ENVELOPE_VERSION`.
/// If that constant changes this must change too — covered by the MCP server's
/// integration smoke test.
pub const ENVELOPE_VERSION: u8 = 1;

/// Audit-worker `/v1/audit/append/v2` request body. Mirrors
/// `agentkeys_worker_audit::handlers::AppendV2Request`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendV2 {
    pub version: u8,
    pub ts_unix: u64,
    pub actor_omni: String,
    pub operator_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
    pub intent_commitment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditAppendV2Resp {
    pub ok: bool,
    pub envelope_hash: String,
}

// ── high-level inputs / results (what the trait/callers pass + get back) ─────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutInput {
    pub cap: CapToken,
    pub namespace: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetInput {
    pub cap: CapToken,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPutResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryGetResult {
    pub ok: bool,
    pub plaintext_b64: String,
    pub namespace: String,
}

/// #295 P1 §7a — request body for the broker `POST /v1/cap/canonical-sts`.
/// The delegate presents its broker-minted `CanonicalFetch` cap (and its OWN
/// session JWT as the Bearer) and receives read-only, exact-object STS creds.
/// The operator session bearer never enters the delegate runtime (the Codex
/// critical fix: the broker, not the client, holds operator authority).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalStsBody {
    pub cap: CapToken,
}

/// Response from `/v1/cap/canonical-sts`: scoped (read-only, single-object) STS
/// creds the delegate relays as `X-Aws-*` to `/v1/memory/canonical-get`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalStsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
}

// ── #441 speech plane — cap→STS relay (epic #439 stack ②) ────────────────────

/// Request body for the broker `POST /v1/cap/speech-sts`. The actor presents
/// its broker-minted `SpeechUse` cap (and its OWN session JWT as the Bearer)
/// and receives short-TTL creds valid ONLY for Transcribe streaming + Polly
/// synthesis. No server-held speech token exists on this stack — the relay is
/// the SAME cap→STS pattern as storage/channels (the epic's consistent-auth
/// principle; the VE stack's #386 app-token custody is the documented gap).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeechStsBody {
    pub cap: CapToken,
}

/// Response from `/v1/cap/speech-sts`. `region` tells the client where to
/// point the Transcribe/Polly SDKs (the broker's own AWS region).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeechStsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
    pub region: String,
}

// ── #512 signer sign-sts — intent-based credential mint (ADR
//    docs/spec/stacks/ve-sts-signing-split.md) ─────────────────────────────────

/// Request body for the SIGNER's `POST /dev/sign-sts` (NOT a broker endpoint —
/// the signer-only listener serves it, bearer = the caller's session JWT).
/// Intent-based: the caller names WHAT it wants (`data_class`, `verbs`,
/// `ttl_seconds`) and proves WHO it is (the JWT; `omni_account` is the
/// standard `/dev/*` cross-check field). The signer renders the session
/// policy ITSELF from this intent — no caller-authored policy string exists,
/// so the ADR's rule 2 (policy ⊆ actor prefix) holds by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStsBody {
    /// Bare/0x 64-hex actor omni — must match the session JWT's claim.
    pub omni_account: String,
    /// One of `vault` | `memory` | `config` | `channel` (speech is gate-held
    /// on VE, #386). Selects the per-class role + bucket (#511).
    pub data_class: String,
    /// Subset of `get` | `put` | `delete` | `list` (case-insensitive).
    pub verbs: Vec<String>,
    /// Requested credential TTL; the signer enforces its ceiling (900s).
    pub ttl_seconds: u64,
    /// The broker-minted OIDC JWT the signer exchanges (`AssumeRoleWithOIDC`).
    pub oidc_token: String,
}

/// Response from `/dev/sign-sts`: the scoped short-TTL credentials. Unix-epoch
/// expiration (the VE RFC-3339 `Expiration` is normalized signer-side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignStsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration_unix: i64,
}

// ── #339 P2 — absorption inbox (master-hub "push" / curated merge) ────────────
//
// The mirror of P1's canonical READ, but for WRITE: a delegate proposes a
// learning into the master's staging inbox; the master curates it into canonical
// later. The on-chain authorization is a **distinct** `inbox:<ns>` grant (never
// the `memory:<ns>` read grant — `readOnly` is a dead flag, master-hub-topology.md
// §5/§6b). Like P1's A' model, the cross-actor WRITE runs SERVER-SIDE in the
// worker under a broker-minted, prefix-scoped operator STS — the delegate holds
// NO AWS creds. Provenance (`source_delegate_omni`) is stamped by the WORKER from
// the cap-signed `actor_omni`, NEVER from a delegate-supplied field (§8).

/// The context TYPE of a context-system object (#390, master-hub-topology.md
/// §16 / arch.md §5 "context system"). The lifecycle machinery is uniform; what
/// varies per kind is the **adoption-gate strictness + runtime application**:
/// `knowledge` = light curation, recalled/injected per turn (the original
/// "memory"); `skill` = strict diff-review curation, delivered as files;
/// `persona` = master-authored only (never inbox-adoptable), applied fresh each
/// turn (`SOUL.md`). Wire spelling is the lowercase word; absent = `knowledge`
/// (full back-compat — every pre-#390 object is knowledge). `resource` joins
/// the enum when its gate policy is implemented, not before.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum ContextKind {
    #[default]
    Knowledge,
    Skill,
    Persona,
}

impl ContextKind {
    /// Wire spelling (matches the serde rename) — for hand-built JSON bodies
    /// and log lines, so nobody re-types the lowercase word.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContextKind::Knowledge => "knowledge",
            ContextKind::Skill => "skill",
            ContextKind::Persona => "persona",
        }
    }

    /// Parse the wire spelling (CLI flags, env) — the inverse of [`Self::as_str`].
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "knowledge" => Some(ContextKind::Knowledge),
            "skill" => Some(ContextKind::Skill),
            "persona" => Some(ContextKind::Persona),
            _ => None,
        }
    }
}

/// The RESERVED canonical namespace persona documents live in (#390). Written
/// ONLY by the daemon's persona editor (master-authored); never granted to a
/// delegate (`memory:persona` / `inbox:persona` are never offered), never
/// reconciled into the recall taxonomy, and the master-memory plant rejects
/// direct writes into it — the persona module is the single writer.
pub const PERSONA_NAMESPACE: &str = "persona";

/// Canonical persona-document key for one delegate within
/// [`PERSONA_NAMESPACE`]: `soul:<0x-omni-lowercase>`. Version-history entries
/// append `@<n>` (see the daemon persona module) — spell it through this
/// helper so the key shape has one owner.
pub fn persona_soul_key(delegate_omni: &str) -> String {
    format!("soul:{}", normalize_omni_0x(delegate_omni).to_lowercase())
}

/// Delegate → worker `POST /v1/memory/inbox-append`. The Append cap carries
/// `service = inbox:<ns>` (the SIGNED namespace); `key` is the delegate's
/// proposed memory key within that namespace and `plaintext_b64` the proposed
/// body. `kind` is the delegate's LABEL for what it proposes (a delegate can
/// label its proposal's kind, never its authorship — provenance stays
/// worker-stamped); absent = `knowledge`. The worker stamps provenance +
/// content-hash and writes the envelope to
/// `bots/<operator>/inbox/<delegate>/<ns>/<content_hash>.enc`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInboxAppendBody {
    pub cap: CapToken,
    pub key: String,
    pub plaintext_b64: String,
    #[serde(default)]
    pub kind: ContextKind,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryInboxAppendResp {
    pub ok: bool,
    pub s3_key: String,
    /// sha256 over (ns || key || body) — the dedup key + the curate watermark.
    pub content_hash: String,
    /// Durable-audit receipt (#229) — see [`MemoryPutResp::audit_envelope_hash`].
    #[serde(default)]
    pub audit_envelope_hash: Option<String>,
}

/// #339 P2 §8 (A') — request body for the broker `POST /v1/cap/inbox-sts`. The
/// write-side twin of [`CanonicalStsBody`]: the WORKER (not the delegate) relays
/// the delegate's session bearer + the broker-minted `Append` cap and receives
/// PUT-only STS scoped to the single delegate's inbox sub-prefix. The delegate
/// never holds AWS creds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxStsBody {
    pub cap: CapToken,
}

/// Response from `/v1/cap/inbox-sts`: write-scoped STS the worker uses to PUT the
/// one inbox object. Same shape as [`CanonicalStsResult`] but semantically a
/// PutObject grant on `bots/<operator>/inbox/<delegate>/<ns>/*` (single delegate,
/// single namespace) — never read, never another delegate's sub-prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxStsResult {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
}

/// The decrypted inbox proposal — what the worker stores (inside the envelope)
/// and the master reads back to curate. `source_delegate_omni`, `ns`, `ts`, and
/// `content_hash` are **worker-stamped** (the delegate controls only `key` +
/// body bytes); the master must trust attribution, not the delegate (§8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub source_delegate_omni: String,
    pub ns: String,
    pub key: String,
    pub body_b64: String,
    pub content_hash: String,
    pub ts: u64,
    /// #390 — the delegate-labeled context kind (validated + stored by the
    /// worker; absent on pre-#390 envelopes = `knowledge`). Drives the per-kind
    /// curate gate: `persona` is never inbox-adoptable, `skill` requires a
    /// viewed-body confirmation + size cap.
    #[serde(default)]
    pub kind: ContextKind,
}

/// Per-item metadata for the master's inbox listing (the curate queue). Mirrors
/// [`InboxItem`] minus the body; `s3_key` is the handle the master passes to
/// `inbox-get` / `inbox-delete`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItemMeta {
    pub s3_key: String,
    pub source_delegate_omni: String,
    pub ns: String,
    pub key: String,
    pub content_hash: String,
    pub bytes: u64,
    pub ts: u64,
    /// #390 — mirrors [`InboxItem::kind`] into the curate queue so the master's
    /// list can gate per kind without decrypting bodies twice.
    #[serde(default)]
    pub kind: ContextKind,
}

/// Master → worker `POST /v1/memory/inbox-list`. Master-self cap (operator ==
/// actor); the worker lists `bots/<operator>/inbox/**` and returns the curate
/// queue. The handler rejects a non-master-self cap so no delegate can read
/// another delegate's proposals (hub-and-spoke, never mesh — §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxListBody {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboxListResp {
    pub ok: bool,
    pub items: Vec<InboxItemMeta>,
}

/// Master → worker `POST /v1/memory/inbox-get` — read one proposal to review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxGetBody {
    pub cap: CapToken,
    pub s3_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboxGetResp {
    pub ok: bool,
    pub item: InboxItem,
}

/// Master → worker `POST /v1/memory/inbox-delete` — GC after curation
/// (delete-on-accept / discard-on-reject). Master-self.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxDeleteBody {
    pub cap: CapToken,
    pub s3_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InboxDeleteResp {
    pub ok: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchInput {
    pub cap: CapToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredFetchResult {
    pub ok: bool,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreInput {
    pub cap: CapToken,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredStoreResult {
    pub ok: bool,
    pub s3_key: String,
    pub envelope_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendInput {
    pub operator_omni: String,
    pub actor_omni: String,
    pub op_kind: u8,
    pub op_body: Value,
    pub result: u8,
    pub intent_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditAppendResult {
    pub ok: bool,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeResult {
    pub ok: bool,
    pub revocation: String,
    /// Present when `revocation != "online_immediate"` — tells the caller what
    /// kind of revocation actually happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// ── #225 / #164 E7 — on-chain K11-gated agent accept (sponsored executeBatch) ─
//
// The accept becomes ONE P256Account.executeBatch UserOp that lands the device
// binding (P.2) + the scope grant (P.3) atomically, gated by one master K11
// signature. Two broker endpoints, J1_master-gated: `build` assembles + co-signs
// the sponsored op and returns the userOpHash; the daemon K11-signs it; `submit`
// relays the signed op to `EntryPoint.handleOps`. The broker mirrors these shapes
// server-side (it doesn't depend on this crate); the frozen key-set tests in
// `crate::fixtures` pin them so the two sides can't drift.

/// Daemon → broker `POST /v1/accept/build`. The granted scope (`services` +
/// caps) is what the master approved in the pairing UI; the register fields bind
/// the agent device. `operator_omni`/`actor_omni` are `0x`-omni
/// ([`normalize_omni_0x`]); the `u128` caps ride as decimal strings (wire-safe
/// past 2^53; `"0"` = unset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildAcceptUserOpRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub device_key_hash: String,
    pub agent_pop_sig: String,
    pub link_code_redemption: String,
    pub services: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
    /// #408 — the actor being bound is a **device** (a channel endpoint), not a
    /// runtime-hosting delegate. Set by the accept card when the claim is a
    /// device pairing; the broker uses it to WARN when a device accept attaches
    /// ZERO channel grants (§14.10 — a device claim must attach ≥1 channel; the
    /// accept card hard-enforces, the broker warns — a grant-less device actor is
    /// inert, not dangerous). `skip_serializing_if` keeps the pre-#408 body
    /// byte-identical (the frozen key-set + fixtures are unchanged for delegates).
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_device: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Count the channel grants (`channel-pub:<id>` / `channel-sub:<id>`) in an
/// accept/scope `services` list (#408). A DEVICE binds with ONLY channel grants
/// (D6); this is what the §14.10 "≥1 channel" rule counts. Direction-agnostic —
/// a device may be pub-only (camera), sub-only (display), or duplex (console).
pub fn channel_grant_count(services: &[String]) -> usize {
    services
        .iter()
        .filter(|s| {
            let l = s.to_lowercase();
            l.starts_with("channel-pub:") || l.starts_with("channel-sub:")
        })
        .count()
}

/// Whether a bind's `requested_scope` (space- OR comma-delimited service list)
/// is a DEVICE bind — NON-EMPTY and every grant is a channel grant (D6). This is
/// the signal the broker uses to enforce **"device pairing never spawns"** (#409
/// D9): a device is a channel endpoint, so its §10.2 claim must NOT trigger the
/// #377 create-on-pair sandbox spawn (only DELEGATE onboarding spawns). An EMPTY
/// scope is NOT a device (an un-scoped delegate claim awaiting a grant still
/// spawns) — only an explicitly channel-only bind suppresses the spawn.
pub fn scope_is_device_only(requested_scope: &str) -> bool {
    let services: Vec<&str> = requested_scope
        .split([' ', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    !services.is_empty()
        && services.iter().all(|s| {
            let l = s.to_lowercase();
            l.starts_with("channel-pub:") || l.starts_with("channel-sub:")
        })
}

/// ERC-4337 v0.7 `PackedUserOperation`, hex-encoded for the wire. Mirrors
/// `agentkeys_broker_server::sponsor::PackedUserOp`; the daemon fills `signature`
/// with the master's K11 assertion over `user_op_hash`, then returns the whole op
/// to `/v1/accept/submit`.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct WireUserOp {
    pub sender: String,
    pub nonce: String,
    pub init_code: String,
    pub call_data: String,
    pub account_gas_limits: String,
    pub pre_verification_gas: String,
    pub gas_fees: String,
    pub paymaster_and_data: String,
    pub signature: String,
}

/// Broker → daemon response to `/v1/accept/build`. The master signs
/// `user_op_hash` (the `EntryPoint.getUserOpHash` of `user_op`) with K11.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BuildAcceptUserOpResponse {
    pub user_op: WireUserOp,
    pub user_op_hash: String,
    pub entry_point: String,
    #[ts(type = "number")]
    pub chain_id: u64,
}

/// The raw browser WebAuthn assertion (base64url) over the accept `user_op_hash`,
/// as `apps/parent-control/lib/webauthn.ts::getAssertionOverHash` emits it. The
/// broker encodes it into the P256Account UserOp signature; it derives the
/// master's `credIdHash` from `operator_omni`, so the raw `credential_id` here is
/// for cross-checks/audit, not the signer key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptAssertion {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub credential_id: String,
}

/// Daemon → broker `POST /v1/accept/submit` — the op from `build` + the master's
/// browser WebAuthn `assertion` over `user_op_hash`. The broker encodes the
/// assertion into `user_op.signature` (binding the `credIdHash` it derives from
/// the verified J1 session omni, not a body field), then relays to
/// `EntryPoint.handleOps` (Stage B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitAcceptUserOpRequest {
    pub user_op: WireUserOp,
    pub assertion: AcceptAssertion,
}

/// Broker → daemon response to `/v1/accept/submit` (and its `/v1/scope/submit`
/// and `/v1/revoke/submit` siblings — the daemon proxies relay it verbatim to
/// the web frontend, which consumes the generated TS type). Two variants share the
/// shape: confirmed (`tx_hash`/`block_number` set, #97 `audit_envelope_hashes`
/// carrying the control-plane AuditEnvelope receipts) and receipt-timeout
/// (`pending: true`, empty `tx_hash`/`block_number`, no envelopes — the op may
/// still mine; the UI confirms on chain by `user_op_hash`).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SubmitAcceptUserOpResponse {
    pub ok: bool,
    pub tx_hash: String,
    pub block_number: String,
    /// The ERC-4337 userOpHash the bundler accepted (#97).
    pub user_op_hash: String,
    /// #97: control-plane audit receipts decoded from the confirmed
    /// executeBatch. Absent on the pending variant / pre-#97 brokers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub audit_envelope_hashes: Option<Vec<String>>,
    /// #230: broadcast but receipt-poll timed out — NOT an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub pending: Option<bool>,
    /// #427: present when the confirmed batch was a spawn/archive ceremony —
    /// the finalization summary (`spawned[]`/`archived[]`: gate provisioning
    /// status, sandbox provision, `DelegateSpawn`/`DelegateArchive` anchor
    /// hashes). Absent on plain accept/scope/revoke submits and pre-#427
    /// brokers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "unknown")]
    pub ceremony: Option<serde_json::Value>,
}

// ── #248 — on-chain K11-gated scope re-grant for an ALREADY-bound agent ──────
//
// The permissions panel's setScope becomes ONE `P256Account.executeBatch([setScope])`
// UserOp, gated by the master's K11 Touch ID — the scope-only sibling of the accept
// batch (no register; the device binding already exists). Broker endpoints
// `/v1/scope/build` + `/v1/scope/submit`, J1_master-gated; `build` returns the
// `userOpHash` the master K11-signs, `submit` reuses the accept relay shape
// ([`SubmitAcceptUserOpRequest`] → bundler → `EntryPoint.handleOps`). The response
// to `build` is the same [`BuildAcceptUserOpResponse`].

/// Daemon → broker `POST /v1/scope/build`. `services` is the FULL replacement
/// list (`AgentKeysScope.setScope` is set-replace, not incremental); an empty
/// list revokes every grant. `preserve_service_ids` are raw on-chain service
/// ids (`0x`-hex keccak-32) echoed from the scope mirror — grants the panel
/// can't name (e.g. `cred:<service>`) that must SURVIVE a memory-toggle commit;
/// the broker unions them into the new grant. Field conventions match
/// [`BuildAcceptUserOpRequest`] (`0x`-omnis, decimal-string `u128` caps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildScopeUserOpRequest {
    pub operator_omni: String,
    pub actor_omni: String,
    pub services: Vec<String>,
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    pub read_only: bool,
    pub max_per_call: String,
    pub max_per_period: String,
    pub max_total: String,
    pub period_seconds: u32,
}

/// Daemon → broker `POST /v1/revoke/build` — the Touch-ID **unpair** and the
/// #260 master-reset **fleet teardown** (same endpoint, N hashes).
/// `SidecarRegistry.revokeAgentDevice` requires `msg.sender ==
/// operatorMasterWallet`, so for an account-master operator the revoke is a
/// master-account UserOp (`executeBatch([revokeAgentDevice × N])`); no EOA —
/// incl. the deployer script — can sign it. One hash = the single unpair; many
/// = every paired agent revoked in ONE UserOp (one Touch ID) BEFORE the master
/// unbind strands the bindings. The broker skips already-revoked/unregistered
/// hashes (the contract would revert the whole batch on them) and rejects
/// cross-operator ones. Response reuses [`BuildAcceptUserOpResponse`]; submit
/// reuses [`SubmitAcceptUserOpRequest`] at `/v1/revoke/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRevokeUserOpRequest {
    pub operator_omni: String,
    /// The agents' on-chain `SidecarRegistry` device key hashes (`0x` + 64 hex
    /// each).
    pub device_key_hashes: Vec<String>,
}

/// Daemon → broker `POST /v1/register/build` — the #278 D6 ONE-op master
/// register. Collapses the legacy 3-tx ceremony (deployer `createAccount` +
/// `depositTo` + self-funded register UserOp) into a single paymaster-sponsored
/// UserOp = `initCode` (counterfactual `P256AccountFactory.createAccount`) +
/// `executeBatch([registerFirstMasterDevice])`, gated by ONE master K11 Touch ID.
///
/// The request carries ONLY what the broker cannot derive: the master P-256
/// passkey coordinates (`owner_pubkey_x`/`owner_pubkey_y`, `0x`+64hex), the
/// WebAuthn `rpid_hash` (deployment/domain-specific, `0x`+64hex), and the device
/// `roles` bitmap. The broker derives everything omni-keyed from the verified J1
/// session omni — `cred_id_hash` ([`agentkeys_core::erc4337::master_cred_id_hash`]),
/// CREATE2 `salt` ([`master_account_salt`]), `device_key_hash`
/// ([`master_device_key_hash`]), `actor_omni == operator_omni` (a first master IS
/// the operator) — so a client cannot drift them. The predicted `sender` comes
/// from `factory.getAddress(...)` and rides back in
/// [`BuildAcceptUserOpResponse::user_op`]`.sender`; submit reuses
/// [`SubmitAcceptUserOpRequest`] at `/v1/register/submit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRegisterUserOpRequest {
    pub operator_omni: String,
    pub owner_pubkey_x: String,
    pub owner_pubkey_y: String,
    pub rpid_hash: String,
    pub roles: u8,
}

// ── #427 (epic #425) — the delegate SPAWN + ARCHIVE ceremonies ───────────────
//
// Spawn: ONE `P256Account.executeBatch([registerDelegate, setScope])` UserOp,
// ONE master Touch ID — the D9 headless in-band claim as a first-class endpoint
// (no pairing rendezvous). `registerDelegate` consumes an agent slot ATOMICALLY
// (the on-chain business quota; `AgentSlotAllowanceExhausted` reverts the whole
// batch, and the build pre-checks `agentSlots` for a loud early 409
// `agent_slot_allowance_exhausted`). Archive: the revoke op for ONE delegate,
// recording the keep-vs-delete resource choice (#425 O4); the slot frees
// in-contract. Broker endpoints `/v1/agent/spawn/{build,submit}` +
// `/v1/agent/archive/{build,submit}`; both submits reuse
// [`SubmitAcceptUserOpRequest`] / [`SubmitAcceptUserOpResponse`] (the shared
// relay), whose `ceremony` field carries the finalization summary.

/// Daemon → broker `POST /v1/agent/spawn/build`. The broker derives the child
/// omni (`HDKD(O_master, label)`), generates the delegate K10, and assembles
/// the template grants (the delegate's duplex operator-chat channel pair + its
/// `memory:<ns>`) — the caller supplies only the ceremony choices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildSpawnUserOpRequest {
    pub operator_omni: String,
    /// The delegate's name — also the HDKD derivation label
    /// (`^[a-z0-9-]{1,32}$`).
    pub label: String,
    /// Repo preset slug (#428 catalog); `""` = blank spawn. Recorded in the
    /// `DelegateSpawn` anchor + the #424 binding manifest.
    #[serde(default)]
    pub preset_id: String,
    /// The template `memory:<ns>` namespace. `None` ⇒ fresh, named after the
    /// label; `Some` + `memory_inherited` ⇒ an archived delegate's KEPT
    /// namespace (#425 O2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_ns: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub memory_inherited: bool,
}

/// Broker → daemon response to `/v1/agent/spawn/build`: the sponsored-UserOp
/// build envelope ([`BuildAcceptUserOpResponse`] fields) plus the ceremony
/// facts the client renders before the ONE Touch ID.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BuildSpawnUserOpResponse {
    pub user_op: WireUserOp,
    pub user_op_hash: String,
    pub entry_point: String,
    #[ts(type = "number")]
    pub chain_id: u64,
    /// The delegate's HDKD child omni.
    pub actor_omni: String,
    pub device_key_hash: String,
    /// The duplex operator-chat channel id in the template grant (S4).
    pub chat_channel_id: String,
    pub memory_ns: String,
    pub memory_inherited: bool,
    /// The template grant NAMES (their keccak ids are what `setScope` signs).
    pub services: Vec<String>,
    /// Allowance state at build time (pre-consume) — the UI quota meter.
    #[ts(type = "number")]
    pub slots_used: u16,
    #[ts(type = "number")]
    pub slots_total: u16,
}

/// Daemon → broker `POST /v1/agent/archive/build` — archive ONE delegate
/// (`TIER_AGENT`; devices unbind via `/v1/revoke/build`, masters via the
/// recovery flow). The slot returns in-contract; `resources_kept` records the
/// #425 O4 keep-vs-delete choice (kept resources become inheritable; the
/// data-plane teardown of deleted ones is the daemon's follow-through).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildArchiveUserOpRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub resources_kept: bool,
    /// The delegate's `memory:<ns>` name when the caller knows it (grants are
    /// keccak ids on-chain) — recorded for #425 O2 inheritance discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_ns: Option<String>,
}

/// Broker → daemon response to `/v1/agent/archive/build`.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BuildArchiveUserOpResponse {
    pub user_op: WireUserOp,
    pub user_op_hash: String,
    pub entry_point: String,
    #[ts(type = "number")]
    pub chain_id: u64,
    pub device_key_hash: String,
    pub resources_kept: bool,
}

// ── #428 (epic #425 S3/O3) — the broker-served preset catalog ────────────────
//
// A preset is the customization unit for a spawned delegate: persona
// (`SOUL.md`, the #390 `persona` kind) + skills docs (`skills/*.md`) + a
// manifest of SUGGESTIONS. **Content, never authority** — suggested channels /
// context / schedules render as inert affordances; grants only ever come from
// the phase-1 spawn template or an explicit later ceremony. Bundle sources are
// repo-resident (`presets/<id>/`), compiled into the broker (`include_str!`,
// versioned with the deployed ref), served at `GET /v1/presets` (summaries) +
// `GET /v1/presets/:id` (full bundle). A marketplace later means new bundles
// server-side under these SAME wire shapes — no client release.

/// A preset's suggested channel — inert until the operator grants it.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetSuggestedChannel {
    pub id: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub reason_zh: String,
}

/// A preset's suggested context namespace — inert until granted.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetSuggestedContext {
    pub ns: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub reason_zh: String,
}

/// A preset's suggested schedule entry. Phase-2 renders it in the panel; the
/// execution substrate (the #340 in-sandbox job harness) wires up later —
/// the field is DATA, not a live cron.
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetSchedule {
    pub cron: String,
    pub label: String,
    #[serde(default)]
    pub label_zh: String,
    pub prompt: String,
}

/// `preset.json` — the manifest half of a repo-resident bundle (also the
/// catalog-list row). Names/descriptions are bilingual (EN + 中文).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetSummary {
    pub id: String,
    pub version: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub description_zh: String,
    #[serde(default)]
    pub suggested_channels: Vec<PresetSuggestedChannel>,
    #[serde(default)]
    pub suggested_context: Vec<PresetSuggestedContext>,
    #[serde(default)]
    pub schedule: Vec<PresetSchedule>,
}

/// One skills doc of a bundle (`presets/<id>/skills/<filename>`).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetSkillDoc {
    pub filename: String,
    pub content: String,
}

/// `GET /v1/presets/:id` — the full bundle: manifest + persona + skills.
/// `soul_md` is the persona LAYER only (the #390 locked base layer is appended
/// by the system at apply time, never stored in a bundle).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetBundle {
    pub manifest: PresetSummary,
    pub soul_md: String,
    #[serde(default)]
    pub skills: Vec<PresetSkillDoc>,
}

/// `GET /v1/presets` — the catalog. `catalog_version` is the deployed ref the
/// bundles were compiled from (bundle edits ship as a broker redeploy).
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct PresetCatalogResponse {
    pub catalog_version: String,
    pub presets: Vec<PresetSummary>,
}

// ── the daemon's web-API plant contract (#275 tier-3) ───────────────────────

/// The daemon's **web-API plant contract** — the frontend↔daemon surface, as
/// opposed to the broker/worker chain above. It lives in this wasm-safe crate
/// so the browser host (`agentkeys-web-core`) compiles the SAME types the
/// daemon's `ui_bridge` serves: `daemon.ts` gets the route + body from a
/// wasm-exported builder instead of hand-building them, which dissolves the
/// old runtime parity check into the type system (#275, parity-ladder rung 3 —
/// "one code path; violating parity is a compile error"). The contract is
/// still pinned to `e2e/fixtures/web-api/master_memory_plant.json` by a
/// `ui_bridge` unit test, and the REMAINING non-Rust consumer
/// (`e2e/suite-6-web-parity.sh`) is gated against that fixture by
/// `scripts/utils/check-web-api-drift.sh`.
pub mod web_api {
    use serde::{Deserialize, Serialize};

    /// Canonical master-memory plant route — the single source of truth for
    /// the path the React frontend (via the `agentkeys-web-core` wasm export)
    /// and the harness web-parity demo both POST to.
    pub const MASTER_MEMORY_PLANT_ROUTE: &str = "/v1/master/memory/plant";

    /// A master-actor memory entry. `content_hash` is the dedup key —
    /// keccak-free sha256 over (ns || key || body) so a re-plant of the same
    /// content is detected and skipped (the "prevent duplicate plant" gate).
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct ApiMemoryEntry {
        pub ns: String,
        pub key: String,
        pub title: String,
        #[ts(type = "number")]
        pub bytes: u64,
        pub version: String,
        pub updated: String,
        pub preview: String,
        pub body: String,
        #[serde(default)]
        pub content_hash: String,
        /// #390 — the context kind (arch.md §5 "context system"); absent on
        /// pre-#390 durable entries = `knowledge`. Canonical `persona` entries
        /// are written only by the daemon persona module (the plant rejects the
        /// reserved `persona` namespace).
        #[serde(default)]
        pub kind: crate::ContextKind,
    }

    /// `POST` body for [`MASTER_MEMORY_PLANT_ROUTE`].
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct MasterMemoryPlantRequest {
        pub entries: Vec<ApiMemoryEntry>,
    }

    /// Plant outcome. `taxonomy_status` surfaces the durable category-index
    /// write so a configured-Config store failure is NOT hidden behind an
    /// otherwise-successful memory plant: `"ok"` (written), `"unconfigured"`
    /// (Config not set up, cache-only), `"failed: <reason>"` (memory IS
    /// durable but the category index is stale → retry), or
    /// `"skipped: <reason>"` (config-context unavailable).
    #[derive(Clone, Debug, Serialize, Deserialize, ts_rs::TS)]
    #[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
    pub struct MasterMemoryPlantResponse {
        #[ts(type = "number")]
        pub planted: usize,
        #[ts(type = "number")]
        pub skipped: usize,
        #[ts(type = "number")]
        pub total: usize,
        pub taxonomy_status: String,
    }
}

// ── shared protocol helpers (the omni-normalization bug site, centralized) ───

/// Build the signed cap **service** string for a memory namespace —
/// `memory:<ns>`. The broker binds this into the cap's signed `service` field
/// (issue #150), so every caller MUST spell it identically; hand-formatting
/// `format!("memory:{ns}")` in a second place is exactly the per-namespace
/// drift this crate exists to kill.
pub fn service_memory(namespace: &str) -> String {
    format!("memory:{namespace}")
}

/// Build the signed cap **service** string for an absorption-inbox APPEND —
/// `inbox:<ns>` (#339 P2). This is a **distinct** on-chain service-id from
/// [`service_memory`]'s `memory:<ns>` read grant: `keccak("inbox:travel") !=
/// keccak("memory:travel")`, so granting a delegate read of `memory:travel`
/// does NOT let it push to `inbox:travel` (and vice-versa). The asymmetry that
/// `readOnly` should carry on-chain but doesn't is carried by this separate
/// service name instead — see docs/plan/master-hub-topology.md §5/§6b.
pub fn service_inbox(namespace: &str) -> String {
    format!("inbox:{namespace}")
}

/// Build the signed cap **service** string for a channel PUBLISH grant —
/// `channel-pub:<id>` (#406, D2). This is a **distinct** on-chain service-id
/// from [`service_channel_sub`]'s `channel-sub:<id>`: `keccak("channel-pub:cam") !=
/// keccak("channel-sub:cam")`, so a device granted publish on a camera channel
/// can NEVER subscribe to it (and vice-versa) — the direction-denial isolation
/// gate lives in the service name, mirroring the #339 `memory:`/`inbox:` split.
pub fn service_channel_pub(channel_id: &str) -> String {
    format!("channel-pub:{channel_id}")
}

/// Build the signed cap **service** string for a channel SUBSCRIBE grant —
/// `channel-sub:<id>` (#406, D2). Distinct from [`service_channel_pub`].
pub fn service_channel_sub(channel_id: &str) -> String {
    format!("channel-sub:{channel_id}")
}

/// Parse a leading `/alias ` deterministic-routing token from a gateway message
/// (#407 §7.3 — `/alias` is the deterministic override; the advisory router is
/// phase 5). Returns `(Some(alias), remaining_text)` for `"/chef 今晚吃什么"` →
/// `(Some("chef"), "今晚吃什么")`; `(None, text)` when there is no leading slash
/// token. The alias charset is `[a-z0-9_-]` (an agent alias), so a bare `/`
/// or a slash mid-sentence is NOT treated as routing.
pub fn parse_alias(text: &str) -> (Option<String>, String) {
    let trimmed = text.trim_start();
    let Some(rest) = trimmed.strip_prefix('/') else {
        return (None, text.to_string());
    };
    let mut split = rest.splitn(2, char::is_whitespace);
    let alias = split.next().unwrap_or("");
    if alias.is_empty()
        || !alias
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return (None, text.to_string());
    }
    let remaining = split.next().unwrap_or("").trim_start().to_string();
    (Some(alias.to_string()), remaining)
}

/// Normalize an omni to the broker's expected `0x`-prefixed lower-hex shape.
///
/// The broker cap-mint input-validates that `operator_omni`/`actor_omni` start
/// with `0x`, but several upstream sources (the daemon onboarding session, JWT
/// claims) store the omni **bare**. This was the `0x`/bare drift bug #200
/// fixed by normalizing inline in the daemon — now there is ONE normalizer so
/// the next caller can't reintroduce it. Already-`0x` input is returned
/// unchanged (case preserved; the broker lower-cases on its side).
pub fn normalize_omni_0x(omni: &str) -> String {
    if omni.starts_with("0x") || omni.starts_with("0X") {
        omni.to_string()
    } else {
        format!("0x{omni}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_mint_op_roundtrips_paths_and_classes() {
        for (s, path, class) in [
            ("cred_store", "/v1/cap/cred-store", "credentials"),
            ("cred_fetch", "/v1/cap/cred-fetch", "credentials"),
            ("memory_put", "/v1/cap/memory-put", "memory"),
            ("memory_get", "/v1/cap/memory-get", "memory"),
            (
                "memory_canonical_get",
                "/v1/cap/memory-canonical-get",
                "memory",
            ),
            ("memory_append", "/v1/cap/memory-append", "memory"),
            ("config_store", "/v1/cap/config-store", "config"),
            ("config_fetch", "/v1/cap/config-fetch", "config"),
            ("channel_publish", "/v1/cap/channel-pub", "channel"),
            ("channel_subscribe", "/v1/cap/channel-sub", "channel"),
            ("speech_use", "/v1/cap/speech", "speech"),
        ] {
            let op = CapMintOp::parse(s).unwrap();
            assert_eq!(op.broker_path(), path);
            assert_eq!(op.data_class(), class);
        }
        assert!(CapMintOp::parse("bogus").is_none());
    }

    #[test]
    fn channel_op_str_matches_worker_direction() {
        // #406: the K10 cap-PoP preimage uses op_str; it MUST agree byte-for-byte
        // with agentkeys_worker_creds::verify::CapOp::ChannelPublish/Subscribe.
        // Publish and subscribe are DISTINCT signed ops (direction isolation).
        assert_eq!(CapMintOp::ChannelPublish.op_str(), "channel_publish");
        assert_eq!(CapMintOp::ChannelSubscribe.op_str(), "channel_subscribe");
        assert_eq!(CapMintOp::SpeechUse.op_str(), "speech_use");
        assert_ne!(
            CapMintOp::ChannelPublish.op_str(),
            CapMintOp::ChannelSubscribe.op_str()
        );
    }

    #[test]
    fn service_channel_pub_sub_are_distinct_grants() {
        // #406 D2: pub and sub are distinct on-chain service-ids for the SAME
        // channel, so a publish grant can never authorize a subscribe (and
        // vice-versa) — keccak(channel-pub:id) != keccak(channel-sub:id).
        assert_eq!(
            service_channel_pub("cam-frontdoor"),
            "channel-pub:cam-frontdoor"
        );
        assert_eq!(
            service_channel_sub("cam-frontdoor"),
            "channel-sub:cam-frontdoor"
        );
        assert_ne!(
            service_channel_pub("cam-frontdoor"),
            service_channel_sub("cam-frontdoor")
        );
    }

    #[test]
    fn channel_grant_count_counts_only_channel_services() {
        // #408 §14.10: a device binds with ONLY channel grants; count them
        // direction-agnostically. Memory/cred grants don't count.
        let camera = vec!["channel-pub:cam-frontdoor".to_string()];
        assert_eq!(channel_grant_count(&camera), 1);
        let duplex = vec![
            "channel-pub:console".to_string(),
            "channel-sub:console".to_string(),
        ];
        assert_eq!(channel_grant_count(&duplex), 2);
        let delegate = vec!["memory:travel".to_string(), "cred:openrouter".to_string()];
        assert_eq!(channel_grant_count(&delegate), 0);
        assert_eq!(channel_grant_count(&[]), 0);
    }

    #[test]
    fn scope_is_device_only_gates_the_spawn() {
        // #409 D9: a channel-only scope is a device (never spawns); a scope with
        // any memory/cred grant is a delegate (spawns); empty is a delegate.
        assert!(scope_is_device_only("channel-pub:cam-frontdoor"));
        assert!(scope_is_device_only(
            "channel-pub:console channel-sub:console"
        ));
        assert!(scope_is_device_only(
            "channel-sub:display,channel-pub:touch"
        ));
        assert!(!scope_is_device_only("memory:travel"));
        assert!(!scope_is_device_only("channel-pub:cam memory:travel")); // mixed = delegate
        assert!(!scope_is_device_only("")); // un-scoped delegate claim still spawns
        assert!(!scope_is_device_only("   "));
    }

    #[test]
    fn channel_kind_wire_and_feed_semantics() {
        assert_eq!(ChannelKind::default(), ChannelKind::FeedBacked);
        assert_eq!(
            serde_json::to_string(&ChannelKind::Session).unwrap(),
            "\"session\""
        );
        assert_eq!(
            serde_json::to_string(&ChannelKind::FeedBacked).unwrap(),
            "\"feed_backed\""
        );
        assert!(ChannelKind::FeedBacked.has_feed());
        assert!(
            !ChannelKind::Session.has_feed(),
            "session channels have no durable feed"
        );
        // Absent = feed_backed (back-compat: every pre-#408 channel is a feed).
        let old: ChannelKind = serde_json::from_str("\"feed_backed\"").unwrap();
        assert_eq!(old, ChannelKind::FeedBacked);
    }

    #[test]
    fn build_accept_is_device_defaults_false_and_skips() {
        // #408: is_device is back-compat — absent on the wire = false, and a
        // false value is skipped so the pre-#408 accept body is byte-identical.
        let json = serde_json::to_value(BuildAcceptUserOpRequest {
            operator_omni: "0xop".into(),
            actor_omni: "0xactor".into(),
            device_key_hash: "0xdkh".into(),
            agent_pop_sig: "0xsig".into(),
            link_code_redemption: "0xred".into(),
            services: vec!["channel-pub:cam".into()],
            read_only: true,
            max_per_call: "0".into(),
            max_per_period: "0".into(),
            max_total: "0".into(),
            period_seconds: 0,
            is_device: false,
        })
        .unwrap();
        assert!(
            json.get("is_device").is_none(),
            "false is_device must be skipped"
        );
        // A device accept round-trips true.
        let dev: BuildAcceptUserOpRequest = serde_json::from_value(serde_json::json!({
            "operator_omni":"0xop","actor_omni":"0xa","device_key_hash":"0xd",
            "agent_pop_sig":"0xs","link_code_redemption":"0xr","services":["channel-sub:display"],
            "read_only":true,"max_per_call":"0","max_per_period":"0","max_total":"0",
            "period_seconds":0,"is_device":true
        }))
        .unwrap();
        assert!(dev.is_device);
    }

    #[test]
    fn contact_tier_wire_roundtrip_and_template() {
        for t in ContactTier::household_template() {
            assert_eq!(ContactTier::parse(t.as_str()), Some(t));
            assert_eq!(
                serde_json::to_string(&t).unwrap(),
                format!("\"{}\"", t.as_str())
            );
        }
        assert!(
            ContactTier::parse("sovereign").is_none(),
            "phantom tier rejected"
        );
        // Only owner may hold operator-grade reach (the L3 guard).
        assert!(ContactTier::Owner.may_hold_operator_grade_reach());
        assert!(!ContactTier::Kid.may_hold_operator_grade_reach());
        assert!(!ContactTier::Guest.may_hold_operator_grade_reach());
    }

    #[test]
    fn contact_registry_resolves_only_bound_ids() {
        let reg = ContactRegistry {
            bound: vec![Contact {
                contact_id: "c-kid-1".into(),
                transport: "weixin".into(),
                transport_id: "openid-abc".into(),
                display_name: "小明".into(),
                tier: ContactTier::Kid,
                reach: vec!["storyteller".into()],
            }],
            pending: vec![],
            invites: vec![],
        };
        assert_eq!(
            reg.resolve("weixin", "openid-abc").unwrap().contact_id,
            "c-kid-1"
        );
        // Unknown openid → None (the gateway DROPS it, never reaches an agent).
        assert!(reg.resolve("weixin", "openid-stranger").is_none());
        // Right id on the wrong transport → None.
        assert!(reg.resolve("telegram", "openid-abc").is_none());
    }

    #[test]
    fn parse_alias_deterministic_routing() {
        assert_eq!(
            parse_alias("/chef 今晚吃什么"),
            (Some("chef".into()), "今晚吃什么".into())
        );
        assert_eq!(
            parse_alias("  /doorkeeper hi"),
            (Some("doorkeeper".into()), "hi".into())
        );
        // No leading slash → no alias.
        assert_eq!(
            parse_alias("just a message"),
            (None, "just a message".into())
        );
        // A slash mid-sentence is not routing.
        assert_eq!(parse_alias("and/or this"), (None, "and/or this".into()));
        // A bare slash or an invalid alias charset is not routing.
        assert_eq!(parse_alias("/ hello"), (None, "/ hello".into()));
        assert_eq!(parse_alias("/CHEF loud"), (None, "/CHEF loud".into()));
        // Alias with no body.
        assert_eq!(parse_alias("/chef"), (Some("chef".into()), "".into()));
    }

    #[test]
    fn channel_event_producer_is_actor_xor_contact() {
        // §4.1: producer is EXACTLY ONE of a keyed actor XOR a contact — the
        // serde tag makes a two-producer envelope impossible to represent.
        let actor = ChannelEvent {
            event_id: "e1".into(),
            channel_id: "cam-frontdoor".into(),
            direction: ChannelDirection::In,
            producer: ChannelProducer::Actor {
                actor_omni: "0xcam".into(),
            },
            kind: ChannelEventKind::Frame,
            body: None,
            body_ref: Some("bots/0xop/channel/cam-frontdoor/1.bin".into()),
            ts_millis: 1,
            correlation: None,
            audio: None,
        };
        let json = serde_json::to_value(&actor).unwrap();
        assert_eq!(json["producer"]["actor"]["actor_omni"], "0xcam");
        // A contact-produced inbound text event round-trips.
        let contact: ChannelEvent = serde_json::from_value(serde_json::json!({
            "event_id": "e2",
            "channel_id": "family-weixin",
            "direction": "in",
            "producer": {"contact": {"contact_id": "c-kid-1", "tier": "kid"}},
            "kind": "text",
            "body": "d2d1bg==",
            "ts_millis": 2,
        }))
        .unwrap();
        assert!(matches!(contact.producer, ChannelProducer::Contact { .. }));
    }

    #[test]
    fn memory_append_op_str_matches_worker_append() {
        // #339 P2: the K10 cap-PoP preimage uses op_str; it MUST agree byte-for-byte
        // with agentkeys_worker_creds::verify::CapOp::Append.as_str() ("append").
        assert_eq!(CapMintOp::MemoryAppend.op_str(), "append");
        assert_eq!(CapMintOp::MemoryCanonicalGet.op_str(), "canonical_fetch");
    }

    #[test]
    fn channel_audio_params_are_additive_and_backcompat() {
        // #522: absent on the wire = None (every pre-#522 event/publish body
        // still parses); None serializes to NOTHING (fixtures stay byte-stable).
        let old_event: ChannelEvent = serde_json::from_value(serde_json::json!({
            "event_id": "e3",
            "channel_id": "opchat-cook",
            "direction": "in",
            "producer": {"actor": {"actor_omni": "0xdev"}},
            "kind": "audio-clip",
            "body": "AAAA",
            "ts_millis": 3,
        }))
        .unwrap();
        assert!(old_event.audio.is_none());
        let json = serde_json::to_value(&old_event).unwrap();
        assert!(json.get("audio").is_none(), "None must not serialize");
        // Params round-trip, partial fields allowed.
        let with: ChannelEvent = serde_json::from_value(serde_json::json!({
            "event_id": "e4",
            "channel_id": "opchat-cook",
            "direction": "in",
            "producer": {"actor": {"actor_omni": "0xdev"}},
            "kind": "audio-clip",
            "body": "AAAA",
            "ts_millis": 4,
            "audio": {"voice": "zh_female_meilinvyou_moon_bigtts", "speech_rate": 30},
        }))
        .unwrap();
        let p = with.audio.as_ref().unwrap();
        assert_eq!(p.voice.as_deref(), Some("zh_female_meilinvyou_moon_bigtts"));
        assert_eq!(p.speech_rate, Some(30));
        assert!(p.format.is_none());
        let rt = serde_json::to_value(&with).unwrap();
        assert_eq!(rt["audio"]["speech_rate"], 30);
        assert!(rt["audio"].get("format").is_none());
    }

    #[test]
    fn context_kind_wire_spelling_and_default() {
        // §16.2 item 1: wire values are the lowercase words; absent = knowledge
        // (full back-compat — every pre-#390 object is knowledge).
        for (kind, wire) in [
            (ContextKind::Knowledge, "\"knowledge\""),
            (ContextKind::Skill, "\"skill\""),
            (ContextKind::Persona, "\"persona\""),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), wire);
            assert_eq!(kind.as_str(), wire.trim_matches('"'));
        }
        // A pre-#390 InboxItem (no `kind` key) deserializes as knowledge.
        let old: InboxItem = serde_json::from_str(
            r#"{"source_delegate_omni":"0xabc","ns":"travel","key":"k","body_b64":"","content_hash":"h","ts":1}"#,
        )
        .unwrap();
        assert_eq!(old.kind, ContextKind::Knowledge);
        let bad: Result<ContextKind, _> = serde_json::from_str("\"resource\"");
        assert!(bad.is_err(), "resource is not in the wire enum yet (§16.2)");
    }

    #[test]
    fn persona_soul_key_normalizes_omni() {
        // One key shape: 0x-prefixed, lowercased — bare and 0X inputs converge.
        assert_eq!(persona_soul_key("0xAbC1"), "soul:0xabc1");
        assert_eq!(persona_soul_key("abc1"), "soul:0xabc1");
        assert_eq!(PERSONA_NAMESPACE, "persona");
    }

    #[test]
    fn service_memory_is_namespace_prefixed() {
        assert_eq!(service_memory("travel"), "memory:travel");
        assert_eq!(service_memory("webparity"), "memory:webparity");
    }

    #[test]
    fn service_inbox_is_distinct_from_memory_read_grant() {
        // #339 P2 §5/§6b: the append grant is a DISTINCT on-chain service-id from
        // the read grant, so a `memory:<ns>` read can never authorize an
        // `inbox:<ns>` push (keccak(inbox:ns) != keccak(memory:ns)).
        assert_eq!(service_inbox("travel"), "inbox:travel");
        assert_ne!(service_inbox("travel"), service_memory("travel"));
    }

    #[test]
    fn normalize_omni_adds_prefix_once() {
        assert_eq!(normalize_omni_0x("abcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0xabcd"), "0xabcd");
        assert_eq!(normalize_omni_0x("0Xabcd"), "0Xabcd");
    }

    #[test]
    fn broker_cap_request_ttl_is_optional_on_the_wire() {
        // Mirrors the broker's `#[serde(default)]`: `None` omits ttl_seconds (the
        // broker then applies its default), `Some` emits a bare number. This is
        // why the single on-wire type uses `Option` + skip rather than a required
        // `u64` — the divergence web-core and backend-client used to carry.
        let base = BrokerCapRequest {
            operator_omni: "0xop".into(),
            actor_omni: "0xactor".into(),
            service: "memory:travel".into(),
            device_key_hash: "0xdkh".into(),
            ttl_seconds: None,
            client_sig: None,
            client_nonce: None,
            client_ts: None,
            delegation_path: None,
        };
        let omitted = serde_json::to_value(&base).unwrap();
        assert!(
            omitted.get("ttl_seconds").is_none(),
            "None must omit ttl_seconds so the broker applies its default"
        );
        assert!(
            omitted.get("delegation_path").is_none(),
            "None must omit delegation_path so the pre-#369 cap body is byte-identical"
        );
        let present = serde_json::to_value(BrokerCapRequest {
            ttl_seconds: Some(900),
            ..base
        })
        .unwrap();
        assert_eq!(present["ttl_seconds"], 900);
    }
}
