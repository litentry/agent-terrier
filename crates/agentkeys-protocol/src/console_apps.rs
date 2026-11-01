use crate::{
    AppInstallBindings, BoundChannel, EndpointEnrollment, EndpointScope, ResourceKind, Sensitivity,
    SlotBinding,
};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInstallBuildRequest {
    pub template_id: String,
    pub label: String,
    #[serde(default)]
    pub bindings: AppInstallBindings,
    #[serde(default)]
    pub memory_ns: Option<String>,
    #[serde(default)]
    pub memory_inherited: bool,
    /// #663 — fold the not-yet-enrolled endpoint actors the bindings need (the
    /// channel gateway for a messaging slot, this console for a display slot)
    /// into the SAME batch, so the first install is still ONE Touch ID. Off
    /// for headless CI installs (a throwaway runner must not register itself).
    #[serde(default = "default_true")]
    pub enroll_endpoints: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppUninstallBuildRequest {
    #[serde(default)]
    pub resources_kept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCommandRequest {
    /// The display feed (defaults to the app's first display slot).
    #[serde(default)]
    pub channel_id: Option<String>,
    pub action: String,
    pub command: String,
    #[serde(default)]
    pub args: serde_json::Value,
    #[serde(default)]
    pub card_updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAddRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub ns: String,
    /// The item's content (UTF-8 text / markdown / JSON).
    pub body: String,
    /// D-K5 — the `content_hash` of the row this edit started from; a
    /// different current row is refused with 409 `stale_base` (a diff, never
    /// a silent overwrite). Absent for a new item or a deliberate overwrite.
    #[serde(default)]
    pub base_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUploadRequest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_zh: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Vec<String>,
    pub sensitivity: Sensitivity,
    pub ns: String,
    pub filename: String,
    #[serde(default)]
    pub content_type: String,
    /// The file bytes, standard base64.
    pub content_b64: String,
    /// D-K5 — see `ResourceAddRequest::base_content_hash`.
    #[serde(default)]
    pub base_content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRemoveRequest {
    pub id: String,
    /// Remove even while a live app is bound to the item (its `knowledge:<ns>`
    /// grant stays; the entry it read is gone).
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRetypeRequest {
    pub id: String,
    pub kind: ResourceKind,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub sensitivity: Option<Sensitivity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRebindBuildRequest {
    /// `slot → channel_id` for the slots to change; unlisted slots keep their
    /// binding, resources and the audience are untouched. EMPTY = a template
    /// upgrade: the catalog's current version is applied to the installed
    /// app — its grants and slot directions recompiled over the unchanged
    /// bindings.
    #[serde(default)]
    pub slots: Vec<SlotBinding>,
    #[serde(default = "default_true")]
    pub enroll_endpoints: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAnchorsSealRequest {
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebindBuildRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    /// The delegate's FULL new grant set (the compiler's `services`).
    pub services: Vec<String>,
    #[serde(default)]
    pub preserve_service_ids: Vec<String>,
    /// The endpoint actors' FULL resulting sets (the gate that relays the new
    /// channel, the console on a display feed).
    #[serde(default)]
    pub endpoint_scopes: Vec<EndpointScope>,
    /// An endpoint the new channel needs that is not enrolled yet.
    #[serde(default)]
    pub endpoint_enrollments: Vec<EndpointEnrollment>,
    /// The compiled bound channels after the change — what the sealed
    /// context document carries.
    #[serde(default)]
    pub bound_channels: Vec<BoundChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnContextUpdateRequest {
    pub operator_omni: String,
    pub device_key_hash: String,
    #[serde(default)]
    pub bound_channels: Vec<BoundChannel>,
    /// The seal that confirmed with this change (the row caches it).
    #[serde(default)]
    pub context_version: Option<u64>,
    #[serde(default)]
    pub context_hash: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorsBuildRequest {
    pub operator_omni: String,
    /// The delegates to seal (each must be this master's, with a row).
    pub device_key_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RehydrateRequest {
    pub operator_omni: String,
    /// The context document's exact JSON (the entry body on the memory plane).
    pub context_doc: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatSendRequest {
    pub channel_id: String,
    pub text: String,
    /// #693 — `"command"` publishes the text as a command event (`sync` = pull
    /// the knowledge now); absent / anything else = a text turn.
    #[serde(default)]
    pub kind: Option<String>,
    /// #519/#522 — an optional reply voice (Doubao speaker id) + speech rate
    /// (语速 [-50,100]) the operator picked in fleet's converse pane. When a
    /// voice is set, the turn carries `ChannelAudioParams` so the delegate
    /// speaks its reply. Absent = a plain text turn (backward-compatible; the
    /// parent-control web app sends neither).
    #[serde(default)]
    pub voice: Option<String>,
    #[serde(default)]
    pub speech_rate: Option<i32>,
    /// #563 — "I render partials: stream the reply." Forwarded onto the
    /// published turn as the `stream` hint; a delegate that predates #563
    /// ignores it and answers single-shot. Absent (every pre-#563 caller,
    /// incl. the fleet TUI) = today's behavior, so partial events can never
    /// reach a UI that does not merge them.
    #[serde(default)]
    pub stream: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatPollRequest {
    pub channel_id: String,
    #[serde(default)]
    pub after: String,
    #[serde(default)]
    pub wait_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConsoleEnrollRequest {
    #[serde(default)]
    pub label: Option<String>,
}
pub const DISPLAY_FEED_TAIL_DEFAULT: u32 = 120;
pub const CHAT_HISTORY_TAIL_DEFAULT: u32 = 200;

pub const LIFECYCLE_FEED_TAIL: u32 = 40;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptReceiptRequest {
    pub user_op: crate::WireUserOp,
    #[serde(default)]
    pub context_docs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ChannelDefaultsRefreshRequest {
    pub channel_id: String,
}
