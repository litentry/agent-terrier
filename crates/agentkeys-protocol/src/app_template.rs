//! The **app template manifest** — schema, closed kind vocabularies, the
//! fail-closed validator and the grant compiler (#662, epic #660; plan
//! `docs/plan/family-applications.md` §4.3, arch.md §22f).
//!
//! An *application* composes the substrate primitives (devices, channels,
//! delegates, context/memory, resources) into one installable household use
//! case: `template ⊗ grant set ⊗ one delegate ⊗ channel bindings ⊗ context`.
//! The manifest is the additive evolution of the #428 `PresetSummary` — every
//! field is a **kind or a bound, never a domain** (rule F1): a template names
//! `messaging`/`display` slot kinds and `document`/`profile` resource kinds,
//! never "meal" or "fridge". Every existing role preset parses as a template
//! with zero slots (rule F3, additive on a versioned `schema`).
//!
//! ONE owner (D7): the kind enums, the platform caps, the validator and the
//! compiler live here and nowhere else — the compiler is the only place that
//! mints capability strings (through the existing `service_*` builders), so a
//! compiled grant can never drift from what workers verify.

use serde::{Deserialize, Serialize};

use crate::{
    service_channel_pub, service_channel_sub, service_knowledge, service_plugin, service_proposal,
    service_tool, ChannelEventKind, ContactTier, PresetSchedule, PresetSummary,
};
pub use agentkeys_catalog::Sensitivity;

/// The manifest schema range this validator accepts (F3): additive minors keep
/// the number; a breaking change bumps MAX and ships a migration note the
/// validator names in its refusal.
pub const APP_TEMPLATE_SCHEMA_MIN: u32 = 1;
pub const APP_TEMPLATE_SCHEMA_MAX: u32 = 1;
/// The schema a manifest that omits `schema` is read as (every pre-#662 role
/// preset).
pub const APP_TEMPLATE_SCHEMA_DEFAULT: u32 = 1;

/// The runtime's implied plugin mount, surfaced on the sheet as the read-only
/// "Built with" line (spec `delegate-runtime-dsh.md` §4.3): the dsh memory
/// plugin every delegate equips.
pub const BUILT_WITH_PLUGINS: [&str; 1] = ["openviking"];

/// The product-default tool class a template that declares no `tools` gets
/// (owner decision 2026-09-01: web search/fetch is on for new delegates).
pub const DEFAULT_TOOL_CLASSES: [&str; 1] = ["web"];

/// The #108 default household namespaces the distribution mirror probes when
/// an install names none (the daemon's `DEFAULT_NAMESPACES` reads this).
pub const DEFAULT_MIRROR_NAMESPACES: [&str; 4] = ["personal", "family", "work", "travel"];

/// The #614 capability-service vocabulary — the tool classes the guard maps
/// (`tool:<class>`). ONE owner; the daemon's hash→name reverse map and the
/// validator both read this list.
pub const TOOL_CLASSES: [&str; 3] = ["web", "code", "schedule"];

/// Platform caps a manifest may not exceed — the single source of truth the
/// validator checks `budgets` and the list lengths against.
pub mod platform_caps {
    pub const MAX_SLOTS: usize = 16;
    pub const MAX_RESOURCES: usize = 16;
    pub const MAX_TOOLS: usize = 8;
    pub const MAX_SCHEDULES: usize = 12;
    pub const MAX_DISCLOSURES: usize = 16;
    pub const MAX_BINDINGS_PER_SLOT: u8 = 8;
    pub const GATE_TOKENS_PER_DAY: u64 = 2_000_000;
    pub const GATE_TURNS_PER_HOUR: u32 = 600;
    pub const FEED_EVENTS_PER_DAY: u32 = 5_000;
}

/// The closed channel-kind vocabulary a slot binds by (plan §4.3 / §4.8 —
/// "channel kind"). The `channel-registry` row's `kind` and a manifest slot's
/// `kind` are the same enum. Distinct from [`crate::ChannelKind`], which is
/// the transport SHAPE (feed-backed vs session) of a channel, not what sits at
/// its endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum ChannelEndpointKind {
    /// A contact-gate channel (WeChat / Telegram behind it): contacts write,
    /// the app reads and replies. The bound registry row IS the feed — the
    /// gate registers `<app> → <channel>` at install / rebind and relays that
    /// channel both ways (owner decision 2026-09-22: no derived name).
    Messaging,
    /// An interactive chat feed (the operator chat, a console session).
    Chat,
    /// A card renderer (kitchen screen, console card, LVGL).
    Display,
    Camera,
    Mic,
    Speaker,
    Sensor,
    Actuator,
}

impl ChannelEndpointKind {
    pub const ALL: [ChannelEndpointKind; 8] = [
        ChannelEndpointKind::Messaging,
        ChannelEndpointKind::Chat,
        ChannelEndpointKind::Display,
        ChannelEndpointKind::Camera,
        ChannelEndpointKind::Mic,
        ChannelEndpointKind::Speaker,
        ChannelEndpointKind::Sensor,
        ChannelEndpointKind::Actuator,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ChannelEndpointKind::Messaging => "messaging",
            ChannelEndpointKind::Chat => "chat",
            ChannelEndpointKind::Display => "display",
            ChannelEndpointKind::Camera => "camera",
            ChannelEndpointKind::Mic => "mic",
            ChannelEndpointKind::Speaker => "speaker",
            ChannelEndpointKind::Sensor => "sensor",
            ChannelEndpointKind::Actuator => "actuator",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }
}

/// Which way events flow between the app and a bound channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum SlotDirection {
    /// The app reads the feed (`channel-sub:<id>`).
    Sub,
    /// The app writes the feed (`channel-pub:<id>`).
    Pub,
    /// Both grants.
    Duplex,
}

impl SlotDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            SlotDirection::Sub => "sub",
            SlotDirection::Pub => "pub",
            SlotDirection::Duplex => "duplex",
        }
    }

    pub fn reads(&self) -> bool {
        !matches!(self, SlotDirection::Pub)
    }

    pub fn writes(&self) -> bool {
        !matches!(self, SlotDirection::Sub)
    }
}

/// The closed resource-kind vocabulary (plan §4.5): what SHAPE a curated
/// read-only item has, never what it is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum ResourceKind {
    Document,
    Profile,
    Dataset,
    Gallery,
    /// A plain text entry with no better type (D-K2, `plan/knowledge-repository.md`
    /// §5: every item is typed, the type is metadata). A manifest never asks for
    /// a note; the install wizard retypes one when the owner binds it.
    Note,
}

impl ResourceKind {
    pub const ALL: [ResourceKind; 5] = [
        ResourceKind::Document,
        ResourceKind::Profile,
        ResourceKind::Dataset,
        ResourceKind::Gallery,
        ResourceKind::Note,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceKind::Document => "document",
            ResourceKind::Profile => "profile",
            ResourceKind::Dataset => "dataset",
            ResourceKind::Gallery => "gallery",
            ResourceKind::Note => "note",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == s)
    }
}

/// The app's lifecycle policy (plan §3.4 — app ≠ process): what the broker's
/// lease sweeper does with the sandbox when nothing is happening.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "kebab-case")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum Availability {
    /// The sandbox stays alive (the chat-driven default).
    #[default]
    AlwaysOn,
    /// The sandbox may hibernate; a feed event on a bound sub slot wakes it.
    WakeOnEvent,
    /// The sandbox may hibernate; a schedule tick wakes it.
    Scheduled,
}

impl Availability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Availability::AlwaysOn => "always-on",
            Availability::WakeOnEvent => "wake-on-event",
            Availability::Scheduled => "scheduled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "always-on" => Some(Availability::AlwaysOn),
            "wake-on-event" => Some(Availability::WakeOnEvent),
            "scheduled" => Some(Availability::Scheduled),
            _ => None,
        }
    }

    /// Whether the sweeper may let this app's sandbox sleep.
    pub fn may_hibernate(&self) -> bool {
        !matches!(self, Availability::AlwaysOn)
    }
}

fn default_true() -> bool {
    true
}

fn default_schema() -> u32 {
    APP_TEMPLATE_SCHEMA_DEFAULT
}

/// One typed, bindable channel requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppSlot {
    /// The slot name the template's skills refer to (`family_chat`,
    /// `kitchen_screen`) — `^[a-z0-9_]{1,32}$`, unique within the template.
    pub slot: String,
    pub kind: ChannelEndpointKind,
    pub direction: SlotDirection,
    /// A required slot must be bound at install; an optional one may be
    /// skipped (a household without a kitchen screen still installs).
    #[serde(default = "default_true")]
    pub required: bool,
    /// How many channels may bind this slot (1..=MAX_BINDINGS_PER_SLOT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub max_bindings: Option<u8>,
    /// The event kinds the app expects on / emits into this slot.
    #[serde(default)]
    pub event_kinds: Vec<ChannelEventKind>,
    /// Messaging slots only — the DEFAULT household tiers allowed to reach
    /// the app; the master confirms (or edits) at install and each allowed
    /// contact's `reach` gains the app's alias.
    #[serde(default)]
    pub audience: Vec<ContactTier>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub reason_zh: String,
}

/// One read-only curated-input requirement (a `resource item` is bound to it
/// at install).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppResourceRequest {
    /// `^[a-z0-9_-]{1,32}$`, unique within the template.
    pub name: String,
    pub kind: ResourceKind,
    /// Matching hints for the wizard (never a household name — F1).
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_true")]
    pub required: bool,
    /// The lowest sensitivity the template expects here; a `Sensitive` floor
    /// requires a `disclosure[]` line naming the model path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub sensitivity_floor: Option<Sensitivity>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub reason_zh: String,
}

/// Usage bounds, each ≤ the platform cap.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppBudgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional, type = "number")]
    pub gate_tokens_per_day: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub gate_turns_per_hour: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub feed_events_per_day: Option<u32>,
}

/// One "what leaves your home" line: which data transits which external path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppDisclosure {
    pub data: String,
    #[serde(default)]
    pub data_zh: String,
    pub path: String,
    #[serde(default)]
    pub path_zh: String,
}

fn default_persona_file() -> String {
    "SOUL.md".to_string()
}

/// Content pointers inside the template: which bundle files are the persona,
/// the skills and the knowledge docs. By convention `skills/perception.md`
/// holds the media pre-turn prompts (R2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppContextPointers {
    #[serde(default = "default_persona_file")]
    pub persona: String,
    #[serde(default)]
    pub skills: Vec<String>,
    #[serde(default)]
    pub knowledge: Vec<String>,
}

impl Default for AppContextPointers {
    fn default() -> Self {
        Self {
            persona: default_persona_file(),
            skills: Vec::new(),
            knowledge: Vec::new(),
        }
    }
}

/// The name of the skills doc the R2 perception adapter reads its per-kind
/// prompts from (template content, never framework code — F1).
pub const PERCEPTION_SKILL_FILE: &str = "perception.md";

// ── the manifest fields on PresetSummary ────────────────────────────────────

/// The additive manifest half of [`PresetSummary`] (plan §4.3). Flattened into
/// the preset JSON so `preset.json` stays ONE document; every field defaults so
/// a pre-#662 role preset parses unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppManifest {
    /// Manifest schema version (F3). Absent = [`APP_TEMPLATE_SCHEMA_DEFAULT`].
    #[serde(default = "default_schema")]
    pub schema: u32,
    #[serde(default)]
    pub publisher: String,
    #[serde(default)]
    pub slots: Vec<AppSlot>,
    #[serde(default)]
    pub resources: Vec<AppResourceRequest>,
    /// Capability services the app needs — bare classes (`web`) or the
    /// `tool:<class>` spelling. ABSENT = the product default
    /// ([`DEFAULT_TOOL_CLASSES`]); PRESENT = exactly this set (an empty list
    /// grants no tool class).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tools: Option<Vec<String>>,
    #[serde(default)]
    pub availability: Availability,
    #[serde(default)]
    pub budgets: AppBudgets,
    #[serde(default)]
    pub disclosure: Vec<AppDisclosure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub context: Option<AppContextPointers>,
    /// A synthetic template (the conformance template) the catalog lists only
    /// on a test stack; never offered to a household.
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub hidden: bool,
}

impl Default for AppManifest {
    fn default() -> Self {
        Self {
            schema: APP_TEMPLATE_SCHEMA_DEFAULT,
            publisher: String::new(),
            slots: Vec::new(),
            resources: Vec::new(),
            tools: None,
            availability: Availability::default(),
            budgets: AppBudgets::default(),
            disclosure: Vec::new(),
            context: None,
            hidden: false,
        }
    }
}

impl PresetSummary {
    /// A template that composes at least one primitive (a slot, a resource, or
    /// an explicit tool set) is an **application**; a zero-slot template is a
    /// role preset and compiles to today's spawn template byte-for-byte.
    pub fn is_application(&self) -> bool {
        !self.app.slots.is_empty() || !self.app.resources.is_empty() || self.app.tools.is_some()
    }

    /// The resolved tool classes (declared, else the product default), bare.
    pub fn tool_classes(&self) -> Vec<String> {
        match &self.app.tools {
            None => DEFAULT_TOOL_CLASSES.iter().map(|c| c.to_string()).collect(),
            Some(list) => {
                let mut out: Vec<String> = Vec::new();
                for t in list {
                    let class = normalize_tool_class(t);
                    if !out.contains(&class) {
                        out.push(class);
                    }
                }
                out
            }
        }
    }
}

/// `tool:web` → `web`; `web` → `web`; whitespace/case-normalized.
pub fn normalize_tool_class(spelling: &str) -> String {
    let s = spelling.trim().to_ascii_lowercase();
    s.strip_prefix("tool:").unwrap_or(&s).to_string()
}

// ── validation ──────────────────────────────────────────────────────────────

/// One refused manifest row: the field path + a human-readable reason (the
/// wizard shows it before the sheet ever renders). `code` is stable for tests
/// and telemetry; `message` is for people.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct TemplateError {
    pub row: String,
    pub code: String,
    pub message: String,
}

impl TemplateError {
    fn new(row: impl Into<String>, code: &str, message: impl Into<String>) -> Self {
        Self {
            row: row.into(),
            code: code.to_string(),
            message: message.into(),
        }
    }
}

/// The label charset the chain's HDKD derivation accepts (`^[a-z0-9-]{1,32}$`
/// — `agentkeys_core::actor_omni::validate_label`); a template id doubles as
/// the default delegate label, so it obeys the same rule.
pub fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_valid_slot_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_valid_resource_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// `MAJOR.MINOR.PATCH`, numeric, no leading `v`.
pub fn is_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The media event kinds whose transit to a model must be disclosed.
pub fn is_media_kind(kind: ChannelEventKind) -> bool {
    matches!(
        kind,
        ChannelEventKind::Image | ChannelEventKind::AudioClip | ChannelEventKind::Frame
    )
}

/// Validate a template against the bundle it ships in (for the `context`
/// pointers) — fail-closed, every violated row reported. `skill_files` /
/// `knowledge_files` are the bundle's doc filenames.
pub fn validate_template(
    summary: &PresetSummary,
    skill_files: &[String],
    knowledge_files: &[String],
) -> Result<(), Vec<TemplateError>> {
    let mut errs: Vec<TemplateError> = Vec::new();
    let m = &summary.app;

    if m.schema < APP_TEMPLATE_SCHEMA_MIN || m.schema > APP_TEMPLATE_SCHEMA_MAX {
        errs.push(TemplateError::new(
            "schema",
            "schema_unsupported",
            format!(
                "manifest schema {} is outside the supported range {}..={} — a newer platform \
                 (or a migration note for a major bump) is needed to install this template",
                m.schema, APP_TEMPLATE_SCHEMA_MIN, APP_TEMPLATE_SCHEMA_MAX
            ),
        ));
    }
    if !is_valid_label(&summary.id) {
        errs.push(TemplateError::new(
            "id",
            "id_charset",
            format!(
                "template id '{}' must match ^[a-z0-9-]{{1,32}}$ (it doubles as the delegate label)",
                summary.id
            ),
        ));
    }
    if !is_semver(&summary.version) {
        errs.push(TemplateError::new(
            "version",
            "version_not_semver",
            format!(
                "template version '{}' must be MAJOR.MINOR.PATCH",
                summary.version
            ),
        ));
    }

    // slots
    if m.slots.len() > platform_caps::MAX_SLOTS {
        errs.push(TemplateError::new(
            "slots",
            "too_many_slots",
            format!(
                "{} slots exceed the platform cap of {}",
                m.slots.len(),
                platform_caps::MAX_SLOTS
            ),
        ));
    }
    let mut seen_slots: Vec<&str> = Vec::new();
    for (i, s) in m.slots.iter().enumerate() {
        let row = format!("slots[{i}]");
        if !is_valid_slot_name(&s.slot) {
            errs.push(TemplateError::new(
                format!("{row}.slot"),
                "slot_name_charset",
                format!("slot name '{}' must match ^[a-z0-9_]{{1,32}}$", s.slot),
            ));
        }
        if seen_slots.contains(&s.slot.as_str()) {
            errs.push(TemplateError::new(
                format!("{row}.slot"),
                "slot_name_duplicate",
                format!("slot name '{}' is declared twice", s.slot),
            ));
        }
        seen_slots.push(&s.slot);
        if s.event_kinds.is_empty() {
            errs.push(TemplateError::new(
                format!("{row}.event_kinds"),
                "slot_event_kinds_empty",
                format!(
                    "slot '{}' declares no event kinds — name what it carries (text, image, doc, …)",
                    s.slot
                ),
            ));
        }
        if let Some(max) = s.max_bindings {
            if max == 0 || max > platform_caps::MAX_BINDINGS_PER_SLOT {
                errs.push(TemplateError::new(
                    format!("{row}.max_bindings"),
                    "slot_max_bindings_range",
                    format!(
                        "slot '{}' max_bindings must be 1..={}",
                        s.slot,
                        platform_caps::MAX_BINDINGS_PER_SLOT
                    ),
                ));
            }
        }
        if !s.audience.is_empty() && s.kind != ChannelEndpointKind::Messaging {
            errs.push(TemplateError::new(
                format!("{row}.audience"),
                "audience_on_non_messaging_slot",
                format!(
                    "slot '{}' is a {} slot — audience tiers only apply to messaging slots",
                    s.slot,
                    s.kind.as_str()
                ),
            ));
        }
        if s.kind == ChannelEndpointKind::Messaging && !s.direction.reads() {
            errs.push(TemplateError::new(
                format!("{row}.direction"),
                "messaging_slot_must_read",
                format!(
                    "messaging slot '{}' must be sub or duplex — a contact's message has to reach the app",
                    s.slot
                ),
            ));
        }
    }

    // resources
    if m.resources.len() > platform_caps::MAX_RESOURCES {
        errs.push(TemplateError::new(
            "resources",
            "too_many_resources",
            format!(
                "{} resources exceed the platform cap of {}",
                m.resources.len(),
                platform_caps::MAX_RESOURCES
            ),
        ));
    }
    let mut seen_res: Vec<&str> = Vec::new();
    let mut sensitive_floor = false;
    for (i, r) in m.resources.iter().enumerate() {
        let row = format!("resources[{i}]");
        if !is_valid_resource_name(&r.name) {
            errs.push(TemplateError::new(
                format!("{row}.name"),
                "resource_name_charset",
                format!("resource name '{}' must match ^[a-z0-9_-]{{1,32}}$", r.name),
            ));
        }
        if seen_res.contains(&r.name.as_str()) {
            errs.push(TemplateError::new(
                format!("{row}.name"),
                "resource_name_duplicate",
                format!("resource name '{}' is declared twice", r.name),
            ));
        }
        seen_res.push(&r.name);
        if r.sensitivity_floor == Some(Sensitivity::Sensitive) {
            sensitive_floor = true;
        }
    }

    // tools
    let mut wants_schedule = false;
    if let Some(list) = &m.tools {
        if list.len() > platform_caps::MAX_TOOLS {
            errs.push(TemplateError::new(
                "tools",
                "too_many_tools",
                format!(
                    "{} tool entries exceed the platform cap of {}",
                    list.len(),
                    platform_caps::MAX_TOOLS
                ),
            ));
        }
        for (i, t) in list.iter().enumerate() {
            let class = normalize_tool_class(t);
            if !TOOL_CLASSES.contains(&class.as_str()) {
                errs.push(TemplateError::new(
                    format!("tools[{i}]"),
                    "tool_class_unknown",
                    format!(
                        "'{t}' is not a known tool class (known: {})",
                        TOOL_CLASSES.join(", ")
                    ),
                ));
            }
            if class == "schedule" {
                wants_schedule = true;
            }
        }
    }

    // schedule
    if summary.schedule.len() > platform_caps::MAX_SCHEDULES {
        errs.push(TemplateError::new(
            "schedule",
            "too_many_schedules",
            format!(
                "{} schedule entries exceed the platform cap of {}",
                summary.schedule.len(),
                platform_caps::MAX_SCHEDULES
            ),
        ));
    }
    for (i, s) in summary.schedule.iter().enumerate() {
        if let Err(why) = validate_cron(&s.cron) {
            errs.push(TemplateError::new(
                format!("schedule[{i}].cron"),
                "cron_syntax",
                format!("'{}': {why}", s.cron),
            ));
        }
        if s.prompt.trim().is_empty() {
            errs.push(TemplateError::new(
                format!("schedule[{i}].prompt"),
                "schedule_prompt_empty",
                "a schedule entry needs the prompt its turn runs",
            ));
        }
    }
    if !summary.schedule.is_empty() && m.tools.is_some() && !wants_schedule {
        errs.push(TemplateError::new(
            "schedule",
            "schedule_requires_tool",
            "the template declares schedule entries but its tools omit `tool:schedule` — timed \
             turns run only under that capability",
        ));
    }

    // budgets
    if let Some(v) = m.budgets.gate_tokens_per_day {
        if v == 0 || v > platform_caps::GATE_TOKENS_PER_DAY {
            errs.push(TemplateError::new(
                "budgets.gate_tokens_per_day",
                "budget_over_cap",
                format!("{v} is outside 1..={}", platform_caps::GATE_TOKENS_PER_DAY),
            ));
        }
    }
    if let Some(v) = m.budgets.gate_turns_per_hour {
        if v == 0 || v > platform_caps::GATE_TURNS_PER_HOUR {
            errs.push(TemplateError::new(
                "budgets.gate_turns_per_hour",
                "budget_over_cap",
                format!("{v} is outside 1..={}", platform_caps::GATE_TURNS_PER_HOUR),
            ));
        }
    }
    if let Some(v) = m.budgets.feed_events_per_day {
        if v == 0 || v > platform_caps::FEED_EVENTS_PER_DAY {
            errs.push(TemplateError::new(
                "budgets.feed_events_per_day",
                "budget_over_cap",
                format!("{v} is outside 1..={}", platform_caps::FEED_EVENTS_PER_DAY),
            ));
        }
    }

    // disclosure
    if m.disclosure.len() > platform_caps::MAX_DISCLOSURES {
        errs.push(TemplateError::new(
            "disclosure",
            "too_many_disclosures",
            format!(
                "{} disclosure lines exceed the platform cap of {}",
                m.disclosure.len(),
                platform_caps::MAX_DISCLOSURES
            ),
        ));
    }
    let carries_media = m
        .slots
        .iter()
        .any(|s| s.event_kinds.iter().any(|k| is_media_kind(*k)));
    if (carries_media || sensitive_floor) && m.disclosure.is_empty() {
        errs.push(TemplateError::new(
            "disclosure",
            "disclosure_required",
            if carries_media {
                "a slot carries media (image / audio-clip / frame) — declare which model path \
                 the media transits in `disclosure[]`"
            } else {
                "a resource declares a Sensitive floor — declare which model path it transits \
                 in `disclosure[]`"
            },
        ));
    }
    for (i, d) in m.disclosure.iter().enumerate() {
        if d.data.trim().is_empty() || d.path.trim().is_empty() {
            errs.push(TemplateError::new(
                format!("disclosure[{i}]"),
                "disclosure_incomplete",
                "each disclosure line names the data AND the path it takes",
            ));
        }
    }

    // context pointers → bundle files
    if let Some(c) = &m.context {
        if c.persona.trim().is_empty() {
            errs.push(TemplateError::new(
                "context.persona",
                "context_file_missing",
                "the persona pointer is empty",
            ));
        }
        for (i, f) in c.skills.iter().enumerate() {
            if !skill_files.iter().any(|x| x == f) {
                errs.push(TemplateError::new(
                    format!("context.skills[{i}]"),
                    "context_file_missing",
                    format!("skills doc '{f}' is not in the bundle"),
                ));
            }
        }
        for (i, f) in c.knowledge.iter().enumerate() {
            if !knowledge_files.iter().any(|x| x == f) {
                errs.push(TemplateError::new(
                    format!("context.knowledge[{i}]"),
                    "context_file_missing",
                    format!("knowledge doc '{f}' is not in the bundle"),
                ));
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

// ── cron (5-field, wasm-safe, no crate) ─────────────────────────────────────

/// Validate a 5-field cron expression (`min hour dom month dow`; `*`, lists,
/// ranges, steps; no names, no seconds field).
pub fn validate_cron(expr: &str) -> Result<(), String> {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "expected 5 fields (min hour day-of-month month day-of-week), got {}",
            fields.len()
        ));
    }
    let bounds: [(u32, u32, &str); 5] = [
        (0, 59, "minute"),
        (0, 23, "hour"),
        (1, 31, "day-of-month"),
        (1, 12, "month"),
        (0, 7, "day-of-week"),
    ];
    for (f, (lo, hi, name)) in fields.iter().zip(bounds.iter()) {
        parse_cron_field(f, *lo, *hi).map_err(|e| format!("{name} field '{f}': {e}"))?;
    }
    Ok(())
}

/// The set of values a cron field matches, as a sorted list.
fn parse_cron_field(field: &str, lo: u32, hi: u32) -> Result<Vec<u32>, String> {
    let mut out: Vec<u32> = Vec::new();
    for part in field.split(',') {
        if part.is_empty() {
            return Err("empty list element".into());
        }
        let (range, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s.parse().map_err(|_| format!("bad step '{s}'"))?;
                if step == 0 {
                    return Err("step must be ≥ 1".into());
                }
                (r, step)
            }
            None => (part, 1),
        };
        let (start, end) = if range == "*" {
            (lo, hi)
        } else if let Some((a, b)) = range.split_once('-') {
            let a: u32 = a.parse().map_err(|_| format!("bad range start '{a}'"))?;
            let b: u32 = b.parse().map_err(|_| format!("bad range end '{b}'"))?;
            if a > b {
                return Err(format!("range {a}-{b} is reversed"));
            }
            (a, b)
        } else {
            let v: u32 = range.parse().map_err(|_| format!("bad value '{range}'"))?;
            // `N/step` means "from N to the field max, every step".
            if step > 1 {
                (v, hi)
            } else {
                (v, v)
            }
        };
        if start < lo || end > hi {
            return Err(format!("value out of range {lo}..={hi}"));
        }
        let mut v = start;
        while v <= end {
            out.push(if hi == 7 && v == 7 { 0 } else { v });
            v += step;
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Whether `expr` fires at the given wall-clock fields (`dow`: 0 = Sunday).
/// Standard cron semantics: when BOTH day-of-month and day-of-week are
/// restricted, either one matching fires.
pub fn cron_matches(expr: &str, minute: u32, hour: u32, dom: u32, month: u32, dow: u32) -> bool {
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return false;
    }
    let f = |i: usize, lo: u32, hi: u32| parse_cron_field(fields[i], lo, hi).ok();
    let (Some(mi), Some(ho), Some(dm), Some(mo), Some(dw)) = (
        f(0, 0, 59),
        f(1, 0, 23),
        f(2, 1, 31),
        f(3, 1, 12),
        f(4, 0, 7),
    ) else {
        return false;
    };
    let dom_restricted = fields[2] != "*";
    let dow_restricted = fields[4] != "*";
    let day_ok = match (dom_restricted, dow_restricted) {
        (true, true) => dm.contains(&dom) || dw.contains(&(dow % 7)),
        (true, false) => dm.contains(&dom),
        (false, true) => dw.contains(&(dow % 7)),
        (false, false) => true,
    };
    mi.contains(&minute) && ho.contains(&hour) && mo.contains(&month) && day_ok
}

// ── install bindings + the compiler ─────────────────────────────────────────

/// One slot → channel binding chosen at install. For a `messaging` slot the
/// `channel_id` is the gateway TRANSPORT id (`weixin`, `telegram`) and the feed
/// the app is granted is derived (`<transport>-<label>`); for every other kind
/// it is the `channel-registry` row id itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SlotBinding {
    pub slot: String,
    pub channel_id: String,
    /// The channel endpoint's own device actor when it has one (the gateway,
    /// the console): the install batch grants IT the feed's other direction
    /// so it can relay in / render + command back. `0x`-omni.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub endpoint_actor_omni: Option<String>,
}

/// One resource request → curated item binding chosen at install. The daemon
/// resolves the registry row and passes the facts the compiler needs (the
/// broker holds no registry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ResourceBinding {
    pub name: String,
    pub item_id: String,
    pub ns: String,
    pub kind: ResourceKind,
    pub sensitivity: Sensitivity,
}

/// The audience the master confirmed for one messaging slot (overrides the
/// template default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct SlotAudience {
    pub slot: String,
    pub tiers: Vec<ContactTier>,
}

/// Everything the master chose in the install wizard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct AppInstallBindings {
    #[serde(default)]
    pub slots: Vec<SlotBinding>,
    #[serde(default)]
    pub resources: Vec<ResourceBinding>,
    #[serde(default)]
    pub audience: Vec<SlotAudience>,
    /// The household's UTC offset for `schedule[]` (minutes east of UTC).
    #[serde(default)]
    pub tz_offset_minutes: i32,
}

/// One feed the sandbox polls / publishes (R1 / R3) — what the durable spawn
/// context carries as `bound_channels`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct BoundChannel {
    pub slot: String,
    pub kind: ChannelEndpointKind,
    pub direction: SlotDirection,
    pub channel_id: String,
    #[serde(default)]
    pub event_kinds: Vec<ChannelEventKind>,
    /// The relaying / rendering endpoint actor (gateway, console) when known —
    /// consumers trust a `contact` stamp on this feed only from this actor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub endpoint_actor_omni: Option<String>,
}

/// What one compiled grant line IS, for the sheet (data vs capability, which
/// slot / resource it serves, its sensitivity tier).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ServiceAnnotation {
    pub service: String,
    /// `opchat` · `own-knowledge` · `own-proposals` · `slot` · `resource` · `tool` · `plugin`
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub sensitivity: Option<Sensitivity>,
}

/// A second actor's grant set the install batch must (re)write alongside the
/// delegate's (set-replace `setScope` per actor): the gateway that relays into
/// a messaging feed, the console that renders + commands a display feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct EndpointGrantDelta {
    pub actor_omni: String,
    /// The service NAMES this install adds for the endpoint actor.
    pub add: Vec<String>,
}

/// The compiler's output — the whole install, derived from manifest + bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CompiledApp {
    /// The delegate's grant set (ordered, deduped) — what `setScope` signs.
    pub services: Vec<String>,
    pub annotations: Vec<ServiceAnnotation>,
    pub bound_channels: Vec<BoundChannel>,
    /// Resolved audience per messaging slot → the alias written into each
    /// allowed contact's `reach`.
    pub audience: Vec<SlotAudience>,
    /// The other actors whose scope the ONE Touch ID also extends.
    pub endpoint_grants: Vec<EndpointGrantDelta>,
    pub memory_ns: String,
    pub chat_channel_id: String,
    pub availability: Availability,
    pub schedule: Vec<PresetSchedule>,
    pub disclosure: Vec<AppDisclosure>,
    /// The bound resources' namespaces (the mirror's probe list).
    pub resource_namespaces: Vec<String>,
}

/// The delegate's own memory namespace for an install: `app-<label>` (unique
/// per instance; the plan's `app-<id>` for the default label = the id).
pub fn app_memory_ns(label: &str) -> String {
    format!("app-{label}")
}

/// The delegate's operator-chat feed id (#425 S4).
pub fn opchat_channel_id(label: &str) -> String {
    format!("opchat-{label}")
}

fn push_unique(services: &mut Vec<String>, s: String) -> bool {
    if services.contains(&s) {
        false
    } else {
        services.push(s);
        true
    }
}

/// Compile manifest + bindings → the grant set and everything derived from it.
/// Validation of the bindings against the template is part of compilation and
/// fail-closed (a required slot left unbound refuses the install). `memory_ns`
/// = `None` ⇒ the derived `app-<label>` (a role preset keeps today's
/// label-named namespace); `Some` ⇒ an inherited namespace (#425 O2).
pub fn compile_app(
    summary: &PresetSummary,
    label: &str,
    memory_ns: Option<&str>,
    bindings: &AppInstallBindings,
) -> Result<CompiledApp, Vec<TemplateError>> {
    let mut errs: Vec<TemplateError> = Vec::new();
    let m = &summary.app;
    let is_app = summary.is_application();

    if !is_valid_label(label) {
        errs.push(TemplateError::new(
            "label",
            "label_charset",
            format!("label '{label}' must match ^[a-z0-9-]{{1,32}}$"),
        ));
    }

    let memory_ns = match memory_ns {
        Some(ns) => ns.to_string(),
        None if is_app => app_memory_ns(label),
        None => label.to_string(),
    };
    let chat_channel_id = opchat_channel_id(label);

    let mut services: Vec<String> = Vec::new();
    let mut annotations: Vec<ServiceAnnotation> = Vec::new();
    let mut bound_channels: Vec<BoundChannel> = Vec::new();
    let mut endpoint_grants: Vec<EndpointGrantDelta> = Vec::new();

    let note = |services: &mut Vec<String>,
                annotations: &mut Vec<ServiceAnnotation>,
                service: String,
                role: &str,
                slot: Option<&str>,
                resource: Option<&str>,
                sensitivity: Option<Sensitivity>| {
        if push_unique(services, service.clone()) {
            annotations.push(ServiceAnnotation {
                service,
                role: role.to_string(),
                slot: slot.map(str::to_string),
                resource: resource.map(str::to_string),
                sensitivity,
            });
        }
    };

    // The derived base — identical to today's spawn template for a role preset.
    note(
        &mut services,
        &mut annotations,
        service_channel_pub(&chat_channel_id),
        "opchat",
        None,
        None,
        None,
    );
    note(
        &mut services,
        &mut annotations,
        service_channel_sub(&chat_channel_id),
        "opchat",
        None,
        None,
        None,
    );
    note(
        &mut services,
        &mut annotations,
        service_knowledge(&memory_ns),
        "own-knowledge",
        None,
        None,
        None,
    );

    // Slots → channel grants (+ the endpoint actor's mirror grants).
    for slot in &m.slots {
        let bound: Vec<&SlotBinding> = bindings
            .slots
            .iter()
            .filter(|b| b.slot == slot.slot)
            .collect();
        let max = slot.max_bindings.unwrap_or(1) as usize;
        if bound.is_empty() && slot.required {
            errs.push(TemplateError::new(
                format!("bindings.slots[{}]", slot.slot),
                "required_slot_unbound",
                format!(
                    "required slot '{}' ({}) has no channel bound",
                    slot.slot,
                    slot.kind.as_str()
                ),
            ));
            continue;
        }
        if bound.len() > max {
            errs.push(TemplateError::new(
                format!("bindings.slots[{}]", slot.slot),
                "slot_over_bound",
                format!(
                    "slot '{}' binds {} channels but allows at most {max}",
                    slot.slot,
                    bound.len()
                ),
            ));
            continue;
        }
        for b in bound {
            if b.channel_id.trim().is_empty() {
                errs.push(TemplateError::new(
                    format!("bindings.slots[{}]", slot.slot),
                    "binding_channel_empty",
                    format!("slot '{}' binding has an empty channel id", slot.slot),
                ));
                continue;
            }
            // The bound channel IS the feed, whatever the slot kind (owner
            // decision 2026-09-22, "channel name is enough"): a messaging
            // slot's channel is what the contact gate relays for this app —
            // the gate learns `<alias> → <channel>` from the install, and the
            // endpoint grants below mirror the channel there. (Until then the
            // feed was derived as `<transport>-<label>`: a second name nobody
            // could see in the registry, and the 2026-09-22 double family
            // chat.)
            let feed = b.channel_id.clone();
            if slot.direction.reads() {
                note(
                    &mut services,
                    &mut annotations,
                    service_channel_sub(&feed),
                    "slot",
                    Some(&slot.slot),
                    None,
                    None,
                );
            }
            if slot.direction.writes() {
                note(
                    &mut services,
                    &mut annotations,
                    service_channel_pub(&feed),
                    "slot",
                    Some(&slot.slot),
                    None,
                    None,
                );
            }
            // A messaging slot is duplex on the wire even when the manifest
            // only reads: the app's reply must reach the contact through the
            // same feed the gateway relays from.
            if slot.kind == ChannelEndpointKind::Messaging && !slot.direction.writes() {
                note(
                    &mut services,
                    &mut annotations,
                    service_channel_pub(&feed),
                    "slot",
                    Some(&slot.slot),
                    None,
                    None,
                );
            }
            if let Some(actor) = b.endpoint_actor_omni.as_deref().filter(|a| !a.is_empty()) {
                // The endpoint mirrors the app: it writes what the app reads
                // and reads what the app writes.
                let mut add: Vec<String> = Vec::new();
                add.push(service_channel_pub(&feed));
                add.push(service_channel_sub(&feed));
                match endpoint_grants.iter_mut().find(|g| g.actor_omni == actor) {
                    Some(g) => {
                        for s in add {
                            push_unique(&mut g.add, s);
                        }
                    }
                    None => endpoint_grants.push(EndpointGrantDelta {
                        actor_omni: actor.to_string(),
                        add,
                    }),
                }
            }
            bound_channels.push(BoundChannel {
                slot: slot.slot.clone(),
                kind: slot.kind,
                direction: slot.direction,
                channel_id: feed,
                event_kinds: slot.event_kinds.clone(),
                endpoint_actor_omni: b.endpoint_actor_omni.clone(),
            });
        }
    }
    for b in &bindings.slots {
        if !m.slots.iter().any(|s| s.slot == b.slot) {
            errs.push(TemplateError::new(
                format!("bindings.slots[{}]", b.slot),
                "binding_unknown_slot",
                format!("'{}' is not a slot of this template", b.slot),
            ));
        }
    }

    // Resources → read-only memory grants.
    let mut resource_namespaces: Vec<String> = Vec::new();
    let mut bound_sensitive = false;
    for req in &m.resources {
        let bound: Vec<&ResourceBinding> = bindings
            .resources
            .iter()
            .filter(|b| b.name == req.name)
            .collect();
        if bound.is_empty() {
            if req.required {
                errs.push(TemplateError::new(
                    format!("bindings.resources[{}]", req.name),
                    "required_resource_unbound",
                    format!(
                        "required resource '{}' ({}) has no item bound",
                        req.name,
                        req.kind.as_str()
                    ),
                ));
            }
            continue;
        }
        for b in bound {
            if b.kind != req.kind {
                errs.push(TemplateError::new(
                    format!("bindings.resources[{}]", req.name),
                    "resource_kind_mismatch",
                    format!(
                        "resource '{}' wants a {} item but '{}' is a {}",
                        req.name,
                        req.kind.as_str(),
                        b.item_id,
                        b.kind.as_str()
                    ),
                ));
                continue;
            }
            if b.ns.trim().is_empty() {
                errs.push(TemplateError::new(
                    format!("bindings.resources[{}]", req.name),
                    "binding_namespace_empty",
                    format!("resource '{}' binding has an empty namespace", req.name),
                ));
                continue;
            }
            if b.ns == memory_ns {
                errs.push(TemplateError::new(
                    format!("bindings.resources[{}]", req.name),
                    "resource_in_own_namespace",
                    format!(
                        "resource '{}' lives in the app's own namespace '{}' — a resource is \
                         read-only by grant shape, so it can never share the namespace the app writes",
                        req.name, memory_ns
                    ),
                ));
                continue;
            }
            if b.sensitivity == Sensitivity::Sensitive {
                bound_sensitive = true;
            }
            note(
                &mut services,
                &mut annotations,
                service_knowledge(&b.ns),
                "resource",
                None,
                Some(&req.name),
                Some(b.sensitivity),
            );
            if !resource_namespaces.contains(&b.ns) {
                resource_namespaces.push(b.ns.clone());
            }
        }
    }
    for b in &bindings.resources {
        if !m.resources.iter().any(|r| r.name == b.name) {
            errs.push(TemplateError::new(
                format!("bindings.resources[{}]", b.name),
                "binding_unknown_resource",
                format!("'{}' is not a resource of this template", b.name),
            ));
        }
    }
    if bound_sensitive && m.disclosure.is_empty() {
        errs.push(TemplateError::new(
            "disclosure",
            "disclosure_required",
            "a Sensitive item is bound — the template must disclose which model path it transits",
        ));
    }

    // The application's own inbox + implied plugin mounts.
    if is_app {
        note(
            &mut services,
            &mut annotations,
            service_proposal(&memory_ns),
            "own-proposals",
            None,
            None,
            None,
        );
    }
    for class in summary.tool_classes() {
        note(
            &mut services,
            &mut annotations,
            service_tool(&class),
            "tool",
            None,
            None,
            None,
        );
    }
    if is_app {
        for p in BUILT_WITH_PLUGINS {
            note(
                &mut services,
                &mut annotations,
                service_plugin(p),
                "plugin",
                None,
                None,
                None,
            );
        }
    }

    // Audience: the master's confirmed tiers override the template default.
    let mut audience: Vec<SlotAudience> = Vec::new();
    for slot in m
        .slots
        .iter()
        .filter(|s| s.kind == ChannelEndpointKind::Messaging)
    {
        if !bound_channels.iter().any(|b| b.slot == slot.slot) {
            continue;
        }
        let tiers = bindings
            .audience
            .iter()
            .find(|a| a.slot == slot.slot)
            .map(|a| a.tiers.clone())
            .unwrap_or_else(|| slot.audience.clone());
        audience.push(SlotAudience {
            slot: slot.slot.clone(),
            tiers,
        });
    }
    for a in &bindings.audience {
        if !m
            .slots
            .iter()
            .any(|s| s.slot == a.slot && s.kind == ChannelEndpointKind::Messaging)
        {
            errs.push(TemplateError::new(
                format!("bindings.audience[{}]", a.slot),
                "audience_unknown_slot",
                format!("'{}' is not a messaging slot of this template", a.slot),
            ));
        }
    }

    if !errs.is_empty() {
        return Err(errs);
    }
    Ok(CompiledApp {
        services,
        annotations,
        bound_channels,
        audience,
        endpoint_grants,
        memory_ns,
        chat_channel_id,
        availability: m.availability,
        schedule: summary.schedule.clone(),
        disclosure: m.disclosure.clone(),
        resource_namespaces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preset(json: &str) -> PresetSummary {
        serde_json::from_str(json).expect("preset parses")
    }

    const CHEF: &str = r#"{
      "schema": 1, "id": "chef", "version": "1.0.0", "name": "Chef", "name_zh": "家庭厨师",
      "availability": "always-on",
      "slots": [
        { "slot": "family_chat", "kind": "messaging", "direction": "sub", "required": true,
          "event_kinds": ["text", "image"], "audience": ["owner", "partner", "elder", "helper"] },
        { "slot": "kitchen_screen", "kind": "display", "direction": "pub", "required": false,
          "event_kinds": ["doc"] }
      ],
      "resources": [
        { "name": "food-preferences", "kind": "profile", "tags": ["diet"], "required": true },
        { "name": "gene-report", "kind": "document", "tags": ["genetics"], "required": false,
          "sensitivity_floor": "sensitive" }
      ],
      "tools": ["tool:schedule", "web"],
      "schedule": [ { "cron": "0 7 * * *", "label": "morning plan", "prompt": "Publish the plan." } ],
      "budgets": { "gate_tokens_per_day": 300000 },
      "disclosure": [ { "data": "meal photos", "path": "gate → vision model" } ]
    }"#;

    fn chef_bindings() -> AppInstallBindings {
        AppInstallBindings {
            slots: vec![
                SlotBinding {
                    slot: "family_chat".into(),
                    channel_id: "family-chat".into(),
                    endpoint_actor_omni: Some("0xgateway".into()),
                },
                SlotBinding {
                    slot: "kitchen_screen".into(),
                    channel_id: "kitchen-display".into(),
                    endpoint_actor_omni: None,
                },
            ],
            resources: vec![
                ResourceBinding {
                    name: "food-preferences".into(),
                    item_id: "prefs-1".into(),
                    ns: "household-preferences".into(),
                    kind: ResourceKind::Profile,
                    sensitivity: Sensitivity::Safe,
                },
                ResourceBinding {
                    name: "gene-report".into(),
                    item_id: "gene-1".into(),
                    ns: "household-health".into(),
                    kind: ResourceKind::Document,
                    sensitivity: Sensitivity::Sensitive,
                },
            ],
            audience: vec![],
            tz_offset_minutes: 480,
        }
    }

    #[test]
    fn legacy_role_preset_parses_as_a_zero_slot_template_and_compiles_to_todays_set() {
        let p = preset(
            r#"{"id":"watchdog","version":"1.0.0","name":"Watchdog","name_zh":"看门狗",
                "suggested_channels":[{"id":"frontdoor-cam"}],"schedule":[]}"#,
        );
        assert_eq!(p.app.schema, 1);
        assert!(!p.is_application());
        assert!(validate_template(&p, &[], &[]).is_ok());
        let c = compile_app(&p, "watchdog", None, &AppInstallBindings::default()).unwrap();
        // Byte-identical to spawn_template_services("opchat-watchdog", "watchdog").
        assert_eq!(
            c.services,
            vec![
                "channel-pub:opchat-watchdog",
                "channel-sub:opchat-watchdog",
                "knowledge:watchdog",
                "tool:web"
            ]
        );
        assert_eq!(c.memory_ns, "watchdog");
        assert!(c.bound_channels.is_empty());
        assert!(c.endpoint_grants.is_empty());
        assert_eq!(c.availability, Availability::AlwaysOn);
    }

    #[test]
    fn chef_validates_and_compiles_the_accept_card() {
        let p = preset(CHEF);
        assert!(p.is_application());
        validate_template(&p, &[], &[]).expect("chef is valid");
        let c = compile_app(&p, "chef", None, &chef_bindings()).expect("chef compiles");
        assert_eq!(
            c.services,
            vec![
                "channel-pub:opchat-chef",
                "channel-sub:opchat-chef",
                "knowledge:app-chef",
                "channel-sub:family-chat",
                "channel-pub:family-chat",
                "channel-pub:kitchen-display",
                "knowledge:household-preferences",
                "knowledge:household-health",
                "proposal:app-chef",
                "tool:schedule",
                "tool:web",
                "plugin:openviking",
            ]
        );
        assert_eq!(c.memory_ns, "app-chef");
        assert_eq!(c.chat_channel_id, "opchat-chef");
        // The gateway mirrors the app on the messaging feed.
        assert_eq!(c.endpoint_grants.len(), 1);
        assert_eq!(c.endpoint_grants[0].actor_omni, "0xgateway");
        assert_eq!(
            c.endpoint_grants[0].add,
            vec!["channel-pub:family-chat", "channel-sub:family-chat"]
        );
        // Bound channels = what the sandbox polls / publishes.
        assert_eq!(c.bound_channels.len(), 2);
        assert_eq!(c.bound_channels[0].channel_id, "family-chat");
        assert_eq!(c.bound_channels[0].kind, ChannelEndpointKind::Messaging);
        assert_eq!(c.bound_channels[1].channel_id, "kitchen-display");
        // Sensitivity rides the annotation for the sheet.
        let gene = c
            .annotations
            .iter()
            .find(|a| a.service == "knowledge:household-health")
            .unwrap();
        assert_eq!(gene.role, "resource");
        assert_eq!(gene.sensitivity, Some(Sensitivity::Sensitive));
        assert_eq!(gene.resource.as_deref(), Some("gene-report"));
        // Audience = the template default (no override).
        assert_eq!(c.audience.len(), 1);
        assert_eq!(c.audience[0].tiers.len(), 4);
        assert_eq!(
            c.resource_namespaces,
            vec!["household-preferences", "household-health"]
        );
    }

    #[test]
    fn audience_override_replaces_the_template_default() {
        let p = preset(CHEF);
        let mut b = chef_bindings();
        b.audience.push(SlotAudience {
            slot: "family_chat".into(),
            tiers: vec![ContactTier::Owner],
        });
        let c = compile_app(&p, "chef", None, &b).unwrap();
        assert_eq!(c.audience[0].tiers, vec![ContactTier::Owner]);
    }

    #[test]
    fn optional_slot_and_resource_may_be_skipped() {
        let p = preset(CHEF);
        let mut b = chef_bindings();
        b.slots.retain(|s| s.slot != "kitchen_screen");
        b.resources.retain(|r| r.name != "gene-report");
        let c = compile_app(&p, "chef", None, &b).unwrap();
        assert!(!c.services.iter().any(|s| s.contains("kitchen-display")));
        assert!(!c.services.iter().any(|s| s.contains("household-health")));
    }

    #[test]
    fn inherited_namespace_is_honored() {
        let p = preset(CHEF);
        let c = compile_app(&p, "chef", Some("kept-chef"), &chef_bindings()).unwrap();
        assert!(c.services.contains(&"knowledge:kept-chef".to_string()));
        assert!(c.services.contains(&"proposal:kept-chef".to_string()));
        assert_eq!(c.memory_ns, "kept-chef");
    }

    // ── every validation row has a negative ──────────────────────────────

    fn codes(r: Result<(), Vec<TemplateError>>) -> Vec<String> {
        r.unwrap_err().into_iter().map(|e| e.code).collect()
    }

    fn ccodes(r: Result<CompiledApp, Vec<TemplateError>>) -> Vec<String> {
        r.unwrap_err().into_iter().map(|e| e.code).collect()
    }

    #[test]
    fn negative_schema_out_of_range() {
        let mut p = preset(CHEF);
        p.app.schema = 99;
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"schema_unsupported".to_string()), "{c:?}");
    }

    #[test]
    fn negative_id_and_version() {
        let mut p = preset(CHEF);
        p.id = "Chef App".into();
        p.version = "v1".into();
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"id_charset".to_string()));
        assert!(c.contains(&"version_not_semver".to_string()));
    }

    #[test]
    fn negative_slot_rows() {
        let mut p = preset(CHEF);
        p.app.slots[0].slot = "Family Chat".into();
        p.app.slots[0].event_kinds.clear();
        p.app.slots[0].max_bindings = Some(0);
        p.app.slots[1].audience = vec![ContactTier::Kid];
        p.app.slots[1].slot = "kitchen_screen".into();
        let mut dup = p.app.slots[1].clone();
        dup.audience.clear();
        p.app.slots.push(dup);
        let c = codes(validate_template(&p, &[], &[]));
        for want in [
            "slot_name_charset",
            "slot_event_kinds_empty",
            "slot_max_bindings_range",
            "audience_on_non_messaging_slot",
            "slot_name_duplicate",
        ] {
            assert!(c.contains(&want.to_string()), "missing {want} in {c:?}");
        }
    }

    #[test]
    fn negative_messaging_slot_must_read() {
        let mut p = preset(CHEF);
        p.app.slots[0].direction = SlotDirection::Pub;
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"messaging_slot_must_read".to_string()));
    }

    #[test]
    fn negative_too_many_slots_and_resources() {
        let mut p = preset(CHEF);
        for i in 0..platform_caps::MAX_SLOTS {
            let mut s = p.app.slots[1].clone();
            s.slot = format!("extra{i}");
            p.app.slots.push(s);
        }
        for i in 0..platform_caps::MAX_RESOURCES {
            let mut r = p.app.resources[0].clone();
            r.name = format!("extra{i}");
            p.app.resources.push(r);
        }
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"too_many_slots".to_string()));
        assert!(c.contains(&"too_many_resources".to_string()));
    }

    #[test]
    fn negative_resource_rows() {
        let mut p = preset(CHEF);
        p.app.resources[0].name = "Food Prefs".into();
        p.app.resources[1].name = "Food Prefs".into();
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"resource_name_charset".to_string()));
        assert!(c.contains(&"resource_name_duplicate".to_string()));
    }

    #[test]
    fn negative_tools_unknown_and_schedule_without_tool() {
        let mut p = preset(CHEF);
        p.app.tools = Some(vec!["tool:teleport".into(), "web".into()]);
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"tool_class_unknown".to_string()));
        assert!(c.contains(&"schedule_requires_tool".to_string()));
        let mut p = preset(CHEF);
        p.app.tools = Some(
            (0..=platform_caps::MAX_TOOLS)
                .map(|_| "web".to_string())
                .collect(),
        );
        assert!(codes(validate_template(&p, &[], &[])).contains(&"too_many_tools".to_string()));
    }

    #[test]
    fn negative_schedule_rows() {
        let mut p = preset(CHEF);
        p.schedule[0].cron = "0 7 * *".into();
        p.schedule[0].prompt = "  ".into();
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"cron_syntax".to_string()));
        assert!(c.contains(&"schedule_prompt_empty".to_string()));
        let mut p = preset(CHEF);
        for _ in 0..platform_caps::MAX_SCHEDULES {
            p.schedule.push(p.schedule[0].clone());
        }
        assert!(codes(validate_template(&p, &[], &[])).contains(&"too_many_schedules".to_string()));
    }

    #[test]
    fn negative_budgets_over_cap() {
        let mut p = preset(CHEF);
        p.app.budgets.gate_tokens_per_day = Some(platform_caps::GATE_TOKENS_PER_DAY + 1);
        p.app.budgets.gate_turns_per_hour = Some(0);
        p.app.budgets.feed_events_per_day = Some(platform_caps::FEED_EVENTS_PER_DAY + 1);
        let c = codes(validate_template(&p, &[], &[]));
        assert_eq!(
            c.iter().filter(|c| c.as_str() == "budget_over_cap").count(),
            3
        );
    }

    #[test]
    fn negative_disclosure_required_for_media_and_sensitive_floor() {
        let mut p = preset(CHEF);
        p.app.disclosure.clear();
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"disclosure_required".to_string()));
        // A text-only template with a Sensitive floor still needs a line.
        let mut p = preset(CHEF);
        p.app.disclosure.clear();
        p.app.slots[0].event_kinds = vec![ChannelEventKind::Text];
        let c = codes(validate_template(&p, &[], &[]));
        assert!(c.contains(&"disclosure_required".to_string()));
        // Neither media nor a Sensitive floor: no disclosure needed.
        let mut p = preset(CHEF);
        p.app.disclosure.clear();
        p.app.slots[0].event_kinds = vec![ChannelEventKind::Text];
        p.app.resources[1].sensitivity_floor = None;
        assert!(validate_template(&p, &[], &[]).is_ok());
        // An incomplete line.
        let mut p = preset(CHEF);
        p.app.disclosure[0].path = String::new();
        assert!(
            codes(validate_template(&p, &[], &[])).contains(&"disclosure_incomplete".to_string())
        );
        let mut p = preset(CHEF);
        for _ in 0..platform_caps::MAX_DISCLOSURES {
            p.app.disclosure.push(p.app.disclosure[0].clone());
        }
        assert!(
            codes(validate_template(&p, &[], &[])).contains(&"too_many_disclosures".to_string())
        );
    }

    #[test]
    fn negative_context_pointers_must_exist_in_the_bundle() {
        let mut p = preset(CHEF);
        p.app.context = Some(AppContextPointers {
            persona: "SOUL.md".into(),
            skills: vec!["perception.md".into(), "missing.md".into()],
            knowledge: vec!["nutrition.md".into()],
        });
        let c = codes(validate_template(&p, &["perception.md".to_string()], &[]));
        assert_eq!(
            c.iter()
                .filter(|c| c.as_str() == "context_file_missing")
                .count(),
            2
        );
        assert!(validate_template(
            &p,
            &["perception.md".to_string(), "missing.md".to_string()],
            &["nutrition.md".to_string()]
        )
        .is_ok());
    }

    #[test]
    fn negative_bindings_at_compile() {
        let p = preset(CHEF);
        // Required slot unbound + required resource unbound + unknown slot.
        let b = AppInstallBindings {
            slots: vec![SlotBinding {
                slot: "nope".into(),
                channel_id: "x".into(),
                endpoint_actor_omni: None,
            }],
            ..Default::default()
        };
        let c = ccodes(compile_app(&p, "chef", None, &b));
        assert!(c.contains(&"required_slot_unbound".to_string()));
        assert!(c.contains(&"required_resource_unbound".to_string()));
        assert!(c.contains(&"binding_unknown_slot".to_string()));
        // Kind mismatch + own namespace + over-bound + unknown resource + bad label.
        let mut b = chef_bindings();
        b.resources[0].kind = ResourceKind::Dataset;
        b.resources[1].ns = "app-chef".into();
        b.resources.push(ResourceBinding {
            name: "nope".into(),
            item_id: "i".into(),
            ns: "n".into(),
            kind: ResourceKind::Document,
            sensitivity: Sensitivity::Safe,
        });
        b.slots.push(SlotBinding {
            slot: "kitchen_screen".into(),
            channel_id: "second-display".into(),
            endpoint_actor_omni: None,
        });
        b.audience.push(SlotAudience {
            slot: "kitchen_screen".into(),
            tiers: vec![],
        });
        let c = ccodes(compile_app(&p, "chef", None, &b));
        for want in [
            "resource_kind_mismatch",
            "resource_in_own_namespace",
            "binding_unknown_resource",
            "slot_over_bound",
            "audience_unknown_slot",
        ] {
            assert!(c.contains(&want.to_string()), "missing {want} in {c:?}");
        }
        let c = ccodes(compile_app(&p, "Chef!", None, &chef_bindings()));
        assert!(c.contains(&"label_charset".to_string()), "{c:?}");
    }

    #[test]
    fn negative_sensitive_binding_requires_disclosure_at_compile() {
        let mut p = preset(CHEF);
        p.app.disclosure.clear();
        p.app.slots[0].event_kinds = vec![ChannelEventKind::Text];
        p.app.resources[1].sensitivity_floor = None;
        assert!(validate_template(&p, &[], &[]).is_ok());
        // The bound item turns out Sensitive at install → refused.
        let c = ccodes(compile_app(&p, "chef", None, &chef_bindings()));
        assert!(c.contains(&"disclosure_required".to_string()));
    }

    #[test]
    fn a_messaging_slot_binds_the_channel_itself() {
        // Owner decision 2026-09-22, "channel name is enough": the channel the
        // slot binds is the feed the app polls AND the one the contact gate
        // mirrors — no `<transport>-<label>` derivation (the double
        // family-chat of 2026-09-22 came from exactly that second name).
        let p = preset(CHEF);
        let mut b = chef_bindings();
        b.slots[0].channel_id = "kitchen-family".into();
        let c = compile_app(&p, "chef", None, &b).expect("compiles");
        assert_eq!(c.bound_channels[0].channel_id, "kitchen-family");
        assert!(c
            .services
            .contains(&"channel-sub:kitchen-family".to_string()));
        assert!(c
            .services
            .contains(&"channel-pub:kitchen-family".to_string()));
        assert_eq!(
            c.endpoint_grants[0].add,
            vec!["channel-pub:kitchen-family", "channel-sub:kitchen-family"]
        );
        assert!(c.services.iter().all(|s| !s.contains("weixin-")));
    }

    #[test]
    fn empty_binding_fields_are_refused() {
        let p = preset(CHEF);
        let mut b = chef_bindings();
        b.slots[0].channel_id = " ".into();
        b.resources[0].ns = String::new();
        let c = ccodes(compile_app(&p, "chef", None, &b));
        assert!(c.contains(&"binding_channel_empty".to_string()));
        assert!(c.contains(&"binding_namespace_empty".to_string()));
    }

    #[test]
    fn tools_absent_is_the_product_default_present_is_authoritative() {
        let p = preset(r#"{"id":"a","version":"1.0.0","name":"A"}"#);
        assert_eq!(p.tool_classes(), vec!["web"]);
        let p = preset(r#"{"id":"a","version":"1.0.0","name":"A","tools":[]}"#);
        assert!(p.tool_classes().is_empty());
        assert!(p.is_application());
        let p =
            preset(r#"{"id":"a","version":"1.0.0","name":"A","tools":["tool:code","code","Web"]}"#);
        assert_eq!(p.tool_classes(), vec!["code", "web"]);
    }

    #[test]
    fn cron_validator_and_matcher() {
        assert!(validate_cron("0 7 * * *").is_ok());
        assert!(validate_cron("*/15 9-17 * * 1-5").is_ok());
        assert!(validate_cron("0 21 * * 0,6").is_ok());
        assert!(validate_cron("60 7 * * *").is_err());
        assert!(validate_cron("0 7 * *").is_err());
        assert!(validate_cron("0 7 * * mon").is_err());
        assert!(validate_cron("0 7 * * */0").is_err());
        assert!(validate_cron("5-1 * * * *").is_err());
        // Wednesday 2026-09-09 07:00.
        assert!(cron_matches("0 7 * * *", 0, 7, 9, 9, 3));
        assert!(!cron_matches("0 7 * * *", 1, 7, 9, 9, 3));
        assert!(cron_matches("*/15 9-17 * * 1-5", 30, 10, 9, 9, 3));
        assert!(!cron_matches("*/15 9-17 * * 1-5", 30, 10, 12, 9, 6));
        // dom OR dow when both are restricted.
        assert!(cron_matches("0 0 1 * 3", 0, 0, 15, 9, 3));
        assert!(cron_matches("0 0 1 * 3", 0, 0, 1, 9, 5));
        assert!(!cron_matches("0 0 1 * 3", 0, 0, 2, 9, 5));
        // 7 = Sunday alias.
        assert!(cron_matches("0 0 * * 7", 0, 0, 13, 9, 0));
    }

    #[test]
    fn wire_spellings_of_the_kind_enums() {
        for k in ChannelEndpointKind::ALL {
            let wire = serde_json::to_string(&k).unwrap();
            assert_eq!(wire, format!("\"{}\"", k.as_str()));
            assert_eq!(ChannelEndpointKind::parse(k.as_str()), Some(k));
        }
        for k in ResourceKind::ALL {
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
            assert_eq!(ResourceKind::parse(k.as_str()), Some(k));
        }
        assert_eq!(
            serde_json::to_string(&Availability::WakeOnEvent).unwrap(),
            "\"wake-on-event\""
        );
        assert_eq!(
            Availability::parse("scheduled"),
            Some(Availability::Scheduled)
        );
        assert!(Availability::AlwaysOn.as_str() == "always-on");
        assert!(!Availability::AlwaysOn.may_hibernate());
        assert!(Availability::Scheduled.may_hibernate());
        assert_eq!(SlotDirection::Duplex.as_str(), "duplex");
        assert!(SlotDirection::Sub.reads() && !SlotDirection::Sub.writes());
        assert!(serde_json::from_str::<ChannelEndpointKind>("\"phone\"").is_err());
        assert!(serde_json::from_str::<ResourceKind>("\"timeseries\"").is_err());
        assert_eq!(ResourceKind::parse("note"), Some(ResourceKind::Note));
    }

    #[test]
    fn derived_names_have_one_owner() {
        assert_eq!(app_memory_ns("chef"), "app-chef");
        assert_eq!(opchat_channel_id("chef"), "opchat-chef");
        assert_eq!(normalize_tool_class(" Tool:Web "), "web");
        assert!(is_valid_label("chef-2"));
        assert!(!is_valid_label("Chef"));
        assert!(is_semver("1.0.0") && !is_semver("1.0") && !is_semver("v1.0.0"));
    }
}

// ─── the delegate's context DOCUMENT — the anchor (owner, 2026-09-22) ────────

/// The key of the context entry in the app's OWN namespace on the memory plane
/// (`knowledge:<memory_ns>`): a `kind: "context"` entry whose `body` is the
/// exact JSON the on-chain seal hashed.
pub const CONTEXT_ENTRY_KEY: &str = "context";

/// The context document's schema version.
pub const CONTEXT_DOC_SCHEMA: u32 = 1;

/// A delegate's runtime context as SEALED on chain and stored on the memory
/// plane — the anchor its bound channels live in: never baked into the image,
/// never only in a broker's row (that row is a cache of this). Never a secret:
/// the K10 stays in the signer, `k10_address` is public. The seal is
/// keccak256 of the exact JSON bytes stored as the entry body, appended to the
/// audit contract as a root (`appendRoot(operator, hash, version)`) inside the
/// SAME batch the owner signs for the install / rebind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct DelegateContextDoc {
    pub schema: u32,
    #[ts(type = "number")]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub previous_hash: Option<String>,
    pub label: String,
    pub device_key_hash: String,
    pub actor_omni: String,
    pub k10_address: String,
    pub preset_id: String,
    pub chat_channel_id: String,
    pub memory_ns: String,
    pub bound_channels: Vec<BoundChannel>,
    pub availability: String,
    pub memory_namespaces: String,
    #[ts(type = "number")]
    pub tz_offset_minutes: i64,
    #[ts(type = "number")]
    pub updated_at: u64,
}

/// What a build returns beside the UserOp when it seals a context: the
/// document bytes the root hashes (stored verbatim after the confirm), the
/// root, the version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ContextSeal {
    pub context_doc: String,
    pub context_hash: String,
    #[ts(type = "number")]
    pub context_version: u64,
}

#[cfg(test)]
mod context_doc_tests {
    use super::*;

    #[test]
    fn the_document_round_trips_and_keeps_its_field_order() {
        let doc = DelegateContextDoc {
            schema: CONTEXT_DOC_SCHEMA,
            version: 2,
            previous_hash: Some("0xabc".into()),
            label: "chef".into(),
            device_key_hash: "0xdkh".into(),
            actor_omni: "0xactor".into(),
            k10_address: "0xk10".into(),
            preset_id: "chef".into(),
            chat_channel_id: "opchat-chef".into(),
            memory_ns: "app-chef".into(),
            bound_channels: vec![],
            availability: "scheduled".into(),
            memory_namespaces: "household-preferences,app-chef".into(),
            tz_offset_minutes: 480,
            updated_at: 1,
        };
        let json = serde_json::to_string(&doc).unwrap();
        assert!(json.starts_with("{\"schema\":1,\"version\":2,\"previous_hash\":\"0xabc\""));
        let back: DelegateContextDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
    }
}
