//! #722 / household channels — the Jev router tier (#689 leg 1): one WeChat
//! thread, and each plain message finds the CHANNEL it belongs on. The
//! decision model (TypeSafe's Jev, reached ONLY through the model gate's
//! `/v1/systemone` relay — the contact gate holds a `gk_` relay key, never a
//! vendor key) answers typed questions over the member's own channels: which
//! channel (`destination`), whether it continues their last conversation
//! (`continues`), and, on a channel several apps are bound to, which app
//! (`addressee:<channel>`). The option set is built from the channel documents
//! that list the member with `speak` and nothing else (owner direction
//! 2026-09-26: the router reads channel documents only — never an app's
//! template), so the model cannot name a channel the member is not on (D10 by
//! construction; [`verdict_from`] re-checks the answer anyway).
//!
//! Owner rules (2026-09-23, recorded in #689 + the plan):
//! - **Unsure → ask the person.** Below the threshold the member gets a
//!   numbered ask naming the top channels; their reply delivers the ORIGINAL
//!   message ([`PendingAsk`], memory-only, TTL). Never a below-threshold route.
//! - **The last channel is context, not a rule.** A continuation («再来一个»,
//!   «好的», «那明天呢») stays on it; a message with its own content goes
//!   where the content points.
//! - **Gate down / no key / malformed → today's deterministic tier**, visibly.
//!
//! Tuned on Kev-9B (the self-hosted System One server), 2026-09-24, on 60
//! labeled Chinese household messages, checked once on 42 held-out ones, each
//! also re-asked with a WRONG previous conversation (a new request must not be
//! pulled into the last one):
//! - The `destination` Choice sees the message only — never the last
//!   conversation. Putting it in the shared state pulled borderline new
//!   requests into the previous conversation, and so did any code-side weight.
//! - A separate `continues` yes/no carries the last conversation in ITS OWN
//!   instructions (so the destination question cannot read it).
//! - Each option is a compact Chinese line; the instructions stay English
//!   (the model's training format).
//! - A pick routes when its probability ≥ 0.5 and strictly beats the
//!   runner-up; a follow-up stays when `continues` ≥ 0.7 and the destination
//!   does not point clearly elsewhere; anything else asks.
//!
//! Harness + numbers: `docs/plan/issue-689-household-small-model.md` §9.
//!
//! Everything that decides is pure (unit-tested); only [`JevClient`] does I/O.

use std::collections::BTreeMap;
use std::time::Duration;

use agentkeys_protocol::{
    ChannelDoc, ChannelEventKind, ContactRegistry, ContactTier, SystemOneQuestion,
    SystemOneRequest, SystemOneResponse, JEV_PINNED_MODEL, SYSTEMONE_ROUTE,
};
use serde_json::{json, Value};

/// The extra option every request carries: "none of the listed channels fits".
pub const UNCLEAR_OPTION: &str = "unclear";
/// The question key the router asks.
pub const DESTINATION_QUESTION: &str = "destination";
/// The follow-up question, asked only when the member has a last channel.
pub const CONTINUES_QUESTION: &str = "continues";
const DESTINATION_INSTRUCTIONS: &str =
    "Which of the household's channels does `message` belong on, and to which \
     assistant there? It was sent by `sender`, a family member of tier \
     `sender_tier`. Each option is a channel — what it is for and who else is in \
     it — with the assistant that would answer there and what that assistant does \
     on it (a channel with several assistants is one option per assistant). A \
     message may ask for something, report something the member did, ate, cooked, \
     bought or noticed, or describe a photo they sent. Pick the option whose \
     purpose covers what the message is about — a report goes where that part of \
     family life is kept track of, just as a request does; a general assistant \
     takes only what no other assistant covers. An assistant's own operator \
     channel is for instructions to that assistant itself (how it should work, \
     its schedule and settings, approving or stopping what it proposed), never \
     for everyday requests.";
const CONTINUES_INSTRUCTIONS: &str =
    "The family member's previous message went to the channel `last_channel`. Is \
     `message` a continuation of that conversation — a short reply, a follow-up \
     question, more detail about what they just shared or showed, or a request \
     for more of the same — rather than a new request for something else?";
const UNCLEAR_CRITERION: &str = "none of the listed channels clearly fits this message";
const CONTINUES_YES: &str = "continues the conversation on `last_channel`";
const CONTINUES_NO: &str = "a new request that stands on its own";
/// How many candidates a numbered ask names.
pub const ASK_CANDIDATES: usize = 3;
/// The placeholder the router view's per-member request carries as `message`.
pub const PREVIEW_MESSAGE: &str = "（成员发来的消息）";

/// Which tier routes a plain text message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterEngine {
    /// Jev when a gate URL + relay key are configured, else deterministic
    /// (the converge-from-state default).
    Auto,
    /// Always try Jev (a missing gate config is a loud boot warning + fallback).
    Jev,
    /// Never call a model — today's whole-word router only.
    Deterministic,
}

impl RouterEngine {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "jev" | "model" => Some(Self::Jev),
            "deterministic" | "off" | "none" => Some(Self::Deterministic),
            _ => None,
        }
    }
}

/// The router tier's settings (`AGENTKEYS_WEIXIN_ROUTER_*` + the gate
/// coordinates). `Default` = deterministic-only (unit tests, a gate-less box).
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub engine: RouterEngine,
    /// The model gate base (`AGENTKEYS_WEIXIN_GATE_URL`, else derived from the
    /// broker host); the relay posts to `<gate>/v1/systemone`.
    pub gate_url: Option<String>,
    /// The contact gate's own `gk_` relay key (`AGENTKEYS_WEIXIN_GATE_KEY[_FILE]`)
    /// — a STACK credential the host setup provisions; attribution = the
    /// household owner (the key record's `user_omni`).
    pub gate_key: Option<String>,
    /// The versioned Jev id sent on every call (thresholds are tuned per version).
    pub model: String,
    /// Route the destination pick only when its probability is at least this
    /// AND strictly above the runner-up; otherwise ask.
    pub threshold: f64,
    /// The gate call's budget; on timeout the deterministic tier runs.
    pub timeout_ms: u64,
    /// How long a numbered ask waits for its reply (memory only).
    pub ask_ttl_secs: u64,
    /// D-M4: a follow-up stays on the last channel when the `continues`
    /// yes/no is at least this (and the destination question does not point
    /// clearly elsewhere). 0.7 sits in the measured gap: follow-ups ≥ 0.77,
    /// new requests after another app ≤ 0.65.
    pub continue_threshold: f64,
    /// Describe a photo with the stack's vision model (through the model
    /// gate) and route the description like a typed message. Off = photos
    /// follow the apps' declared kinds only.
    pub describe_photos: bool,
    /// The description call's budget; on timeout the declared-kinds rule
    /// routes the photo.
    pub describe_timeout_ms: u64,
    /// The Ark model a photo is described with. `None` = the stack's chat
    /// model (the gate fills it in). Must take image input on Ark (D-M7).
    pub describe_model: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            engine: RouterEngine::Auto,
            gate_url: None,
            gate_key: None,
            model: JEV_PINNED_MODEL.to_string(),
            threshold: 0.5,
            timeout_ms: 3000,
            ask_ttl_secs: 600,
            continue_threshold: 0.7,
            describe_photos: true,
            describe_timeout_ms: 8000,
            describe_model: None,
        }
    }
}

impl RouterConfig {
    /// Whether text turns consult the model at all.
    pub fn jev_active(&self) -> bool {
        match self.engine {
            RouterEngine::Deterministic => false,
            RouterEngine::Jev | RouterEngine::Auto => {
                self.gate_url.is_some() && self.gate_key.is_some()
            }
        }
    }

    /// The engine name the logs / monitor / audit carry.
    pub fn engine_label(&self) -> &'static str {
        if self.jev_active() {
            "jev"
        } else {
            "deterministic"
        }
    }
}

/// One app bound to an option channel, as the model reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionApp {
    pub alias: String,
    pub description: String,
    pub takes: Vec<ChannelEventKind>,
}

/// One option the model may pick: a channel the member speaks on, rendered
/// from its document alone — the line is the criterion the model reads. A
/// channel several apps are bound to is offered as one row per app
/// ([`option_keys`], [`ChannelOption::row_line`]), so the pick names the app
/// with the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOption {
    pub id: String,
    pub name: String,
    /// The channel's own line: name, purpose, every app there, the members.
    pub line: String,
    /// The line's head (name and purpose) and tail (the members), for the
    /// per-app rows of a shared channel.
    pub head: String,
    pub members_line: String,
    pub apps: Vec<OptionApp>,
    /// The other members' display names (never a transport id).
    pub members: Vec<String>,
    pub operator_of: Option<String>,
    pub updated_at: u64,
}

/// One key the model picks among: a channel, or one app's row on a channel
/// several apps are bound to (`<channel>/<alias>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionKey {
    pub key: String,
    pub channel: String,
    pub app: Option<String>,
}

/// The keys for a member's options: one per channel, or one per app on a
/// shared channel.
pub fn option_keys(options: &[ChannelOption]) -> Vec<OptionKey> {
    options
        .iter()
        .flat_map(|o| {
            if o.apps.len() >= 2 {
                o.apps
                    .iter()
                    .map(|a| OptionKey {
                        key: format!("{}/{}", o.id, a.alias),
                        channel: o.id.clone(),
                        app: Some(a.alias.clone()),
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![OptionKey {
                    key: o.id.clone(),
                    channel: o.id.clone(),
                    app: None,
                }]
            }
        })
        .collect()
}

impl ChannelOption {
    /// The criterion for one app's row on this (shared) channel: the
    /// channel's head, the app and what it does here, the other apps here,
    /// the members.
    pub fn row_line(&self, alias: &str) -> String {
        let mut line = self.head.clone();
        if let Some(a) = self
            .apps
            .iter()
            .find(|a| a.alias.eq_ignore_ascii_case(alias))
        {
            line.push_str("这条给 ");
            line.push_str(&a.alias);
            if !a.description.is_empty() {
                line.push('（');
                line.push_str(a.description.trim_end_matches('。'));
                line.push('）');
            }
            line.push('。');
        }
        let others: Vec<String> = self
            .apps
            .iter()
            .filter(|a| !a.alias.eq_ignore_ascii_case(alias))
            .map(|a| a.alias.clone())
            .collect();
        if !others.is_empty() {
            line.push_str("也在这里：");
            line.push_str(&others.join("、"));
            line.push('。');
        }
        line.push_str(&self.members_line);
        line
    }

    /// The app an unaddressed turn on this channel goes to (the document's
    /// default, else its only app).
    pub fn default_app(&self, doc_default: Option<&str>) -> Option<String> {
        if let Some(d) = doc_default {
            if self.apps.iter().any(|a| a.alias.eq_ignore_ascii_case(d)) {
                return Some(d.to_lowercase());
            }
        }
        match self.apps.as_slice() {
            [one] => Some(one.alias.clone()),
            _ => None,
        }
    }

    pub fn takes(&self, alias: &str, kind: ChannelEventKind) -> bool {
        self.apps
            .iter()
            .find(|a| a.alias.eq_ignore_ascii_case(alias))
            .is_some_and(|a| a.takes.is_empty() || a.takes.contains(&kind))
    }

    /// The apps here that take `kind`.
    pub fn apps_taking(&self, kind: ChannelEventKind) -> Vec<&OptionApp> {
        self.apps
            .iter()
            .filter(|a| a.takes.is_empty() || a.takes.contains(&kind))
            .collect()
    }
}

fn tier_zh(t: ContactTier) -> &'static str {
    crate::relay::tier_zh(t)
}

/// Render one channel document as the option line the model reads: the
/// name, what the channel is for, the apps bound there with their binding
/// descriptions, and who else is in it. Nothing else — no template, no
/// blurb.
pub fn render_option(
    doc: &ChannelDoc,
    registry: &ContactRegistry,
    for_contact: &str,
) -> ChannelOption {
    let name = doc.display_name().to_string();
    let mut head = match doc.operator_of.as_deref() {
        Some(app) => format!("{name}（{app} 的操作频道）"),
        None => name.clone(),
    };
    let purpose = doc.purpose.trim();
    if !purpose.is_empty() {
        head.push('：');
        head.push_str(purpose);
    }
    head.push('。');
    let mut line = head.clone();
    let apps: Vec<OptionApp> = doc
        .apps
        .iter()
        .map(|a| OptionApp {
            alias: a.alias.to_lowercase(),
            description: a.description.trim().to_string(),
            takes: a.takes.clone(),
        })
        .collect();
    if !apps.is_empty() {
        let listed: Vec<String> = apps
            .iter()
            .map(|a| {
                if a.description.is_empty() {
                    a.alias.clone()
                } else {
                    format!("{}（{}）", a.alias, a.description.trim_end_matches('。'))
                }
            })
            .collect();
        line.push_str("在这里：");
        line.push_str(&listed.join("；"));
        line.push('。');
    }
    let mut speakers: Vec<String> = Vec::new();
    let mut readers: Vec<String> = Vec::new();
    for m in &doc.members {
        if m.contact_id == for_contact {
            continue;
        }
        let Some(c) = registry.contact(&m.contact_id) else {
            continue;
        };
        let who = format!("{}（{}）", c.display_name, tier_zh(c.tier));
        if m.speak {
            speakers.push(who);
        } else if m.read {
            readers.push(who);
        }
    }
    let members: Vec<String> = speakers.iter().chain(readers.iter()).cloned().collect();
    let mut members_line = String::new();
    if speakers.is_empty() && readers.is_empty() {
        members_line.push_str("成员：只有你。");
    } else {
        members_line.push_str("成员：你");
        if !speakers.is_empty() {
            members_line.push('、');
            members_line.push_str(&speakers.join("、"));
        }
        if !readers.is_empty() {
            members_line.push('；');
            members_line.push_str(&readers.join("、"));
            members_line.push_str("只看");
        }
        members_line.push('。');
    }
    line.push_str(&members_line);
    ChannelOption {
        id: doc.id.clone(),
        name,
        line,
        head,
        members_line,
        apps,
        members,
        operator_of: doc.operator_of.clone(),
        updated_at: doc.updated_at,
    }
}

/// The options for a member: every channel document that lists them with
/// `speak`, household channels first, each rendered by [`render_option`].
pub fn channel_options(registry: &ContactRegistry, contact_id: &str) -> Vec<ChannelOption> {
    let mut docs = registry.speak_channels(contact_id);
    docs.sort_by_key(|d| d.is_operator());
    docs.into_iter()
        .map(|d| render_option(d, registry, contact_id))
        .collect()
}

/// Build the request: the `destination` Choice over the member's channels
/// (one row per app on a shared channel) + `unclear`, which sees the message
/// and the sender only; and, when there is a last channel, the `continues`
/// yes/no — the last channel rides in ITS instructions, never in the shared
/// state, so the destination question cannot be pulled toward it.
pub fn build_request(
    model: &str,
    message: &str,
    sender: &str,
    sender_tier: &str,
    last_channel: Option<&str>,
    options: &[ChannelOption],
) -> SystemOneRequest {
    let state = json!({
        "message": message,
        "sender": sender,
        "sender_tier": sender_tier,
    });
    let mut criteria: BTreeMap<String, Value> = BTreeMap::new();
    for k in option_keys(options) {
        if k.key.is_empty() || k.key == UNCLEAR_OPTION {
            continue;
        }
        let o = options
            .iter()
            .find(|o| o.id == k.channel)
            .expect("a key comes from an option");
        let line = match k.app.as_deref() {
            Some(alias) => o.row_line(alias),
            None => o.line.clone(),
        };
        criteria.insert(k.key, Value::String(line));
    }
    criteria.insert(
        UNCLEAR_OPTION.to_string(),
        Value::String(UNCLEAR_CRITERION.into()),
    );
    let mut questions = BTreeMap::new();
    questions.insert(
        DESTINATION_QUESTION.to_string(),
        SystemOneQuestion::Choice {
            instructions: Value::String(DESTINATION_INSTRUCTIONS.to_string()),
            criteria,
        },
    );
    if let Some(last) = last_channel
        .and_then(|l| options.iter().find(|o| o.id == l))
        .map(|o| o.name.clone())
    {
        questions.insert(
            CONTINUES_QUESTION.to_string(),
            SystemOneQuestion::Noul {
                instructions: json!({
                    "last_channel": last,
                    "question": CONTINUES_INSTRUCTIONS,
                }),
                criteria: Some(agentkeys_protocol::NoulCriteria {
                    yes: Some(Value::String(CONTINUES_YES.into())),
                    no: Some(Value::String(CONTINUES_NO.into())),
                }),
            },
        );
    }
    SystemOneRequest {
        model: model.to_string(),
        state,
        questions,
    }
}

/// The guidance every request carries, as the router view shows it.
pub fn guidance() -> agentkeys_protocol::RouterGuidance {
    agentkeys_protocol::RouterGuidance {
        destination: DESTINATION_INSTRUCTIONS.to_string(),
        unclear: UNCLEAR_CRITERION.to_string(),
        continues: CONTINUES_INSTRUCTIONS.to_string(),
        continues_yes: CONTINUES_YES.to_string(),
        continues_no: CONTINUES_NO.to_string(),
        addressee: "A channel several assistants are bound to is offered as one option per assistant (`<channel>/<assistant>`): the pick names both.".to_string(),
    }
}

/// The model's answer, reduced to what the relay acts on.
#[derive(Debug, Clone, PartialEq)]
pub enum JevVerdict {
    /// Confident pick — a channel among the options (its id) and, on a
    /// shared channel, the app the pick named. `follow_up` = it stayed on
    /// the last channel because the message continues that conversation
    /// (the addressee is then the previous turn's, which the relay keeps);
    /// `confidence` is then the `continues` yes/no, otherwise the pick's
    /// probability.
    Route {
        channel: String,
        addressee: Option<String>,
        confidence: f64,
        follow_up: bool,
    },
    /// Below the threshold, a tie, or `unclear`: ask, naming these channels
    /// (best first) — never a guess.
    Ask {
        candidates: Vec<String>,
        confidence: f64,
    },
    /// The answer is not usable (an option we never sent, a missing question,
    /// a wrong answer type). Treated exactly like a transport failure: the
    /// deterministic tier runs. Option-bounding lives here.
    Malformed(String),
}

/// Reduce a response to a verdict. `keys` bounds everything: an option key
/// (or the chosen key) outside `keys ∪ {unclear}` is `Malformed`, never a
/// route.
///
/// 1. A follow-up stays on the last channel: `continues` ≥ `continue_threshold`
///    and the destination question does not point clearly elsewhere (its pick
///    is on the last channel or `unclear`, or it is not a clear pick).
/// 2. Otherwise the destination pick routes when it is not `unclear`, its
///    probability is at least `threshold`, and it is strictly above the
///    runner-up (a tie asks).
/// 3. Otherwise ask, naming the picks' channels best first.
///
/// The statistic is the pick's probability, not the vendor's `confidence`:
/// that formula, (K·p − 1)/(K − 1), shrinks with the number of options, so a
/// 70% pick among three scored 0.55 and asked; Kev's probabilities are
/// temperature-calibrated, which makes the probability itself the "chance this
/// pick is right". A missing `continues` answer counts as "not a follow-up".
pub fn verdict_from(
    resp: &SystemOneResponse,
    keys: &[OptionKey],
    threshold: f64,
    last_channel: Option<&str>,
    continue_threshold: f64,
) -> JevVerdict {
    let Some((choice, probabilities, _vendor_confidence)) = resp.choice(DESTINATION_QUESTION)
    else {
        return JevVerdict::Malformed(format!("no choice answer under `{DESTINATION_QUESTION}`"));
    };
    let canonical = |key: &str| -> Option<&OptionKey> {
        keys.iter()
            .find(|k| k.key.trim().eq_ignore_ascii_case(key.trim()))
    };
    let in_set =
        |key: &str| key.trim().eq_ignore_ascii_case(UNCLEAR_OPTION) || canonical(key).is_some();
    if !in_set(choice) {
        return JevVerdict::Malformed(format!("chose `{choice}`, which is not an option"));
    }
    if let Some(bad) = probabilities.keys().find(|k| !in_set(k)) {
        return JevVerdict::Malformed(format!("option `{bad}` was never offered"));
    }
    let total: f64 = probabilities.values().map(|p| p.max(0.0)).sum();
    if probabilities.is_empty() || total <= 0.0 {
        return JevVerdict::Malformed("empty probabilities".into());
    }

    let mut ranked: Vec<(String, f64)> = probabilities
        .iter()
        .map(|(k, p)| (k.trim().to_lowercase(), p.max(0.0) / total))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let (pick, p1) = ranked[0].clone();
    let p2 = ranked.get(1).map(|(_, p)| *p).unwrap_or(0.0);
    let mut candidates: Vec<String> = Vec::new();
    for (k, _) in ranked.iter().filter(|(k, _)| k.as_str() != UNCLEAR_OPTION) {
        if let Some(key) = canonical(k) {
            if !candidates.contains(&key.channel) {
                candidates.push(key.channel.clone());
            }
        }
        if candidates.len() >= ASK_CANDIDATES {
            break;
        }
    }
    let picked = canonical(&pick);
    let destination_clear = pick != UNCLEAR_OPTION && p1 >= threshold && p1 > p2;

    if let Some(last) = last_channel.filter(|l| keys.iter().any(|k| &k.channel == l)) {
        let continues = resp.noul(CONTINUES_QUESTION).unwrap_or(0.0);
        let points_elsewhere =
            destination_clear && picked.is_some_and(|k| !k.channel.eq_ignore_ascii_case(last));
        if continues >= continue_threshold && !points_elsewhere {
            return JevVerdict::Route {
                channel: last.to_string(),
                addressee: None,
                confidence: continues,
                follow_up: true,
            };
        }
    }
    if !destination_clear {
        return JevVerdict::Ask {
            candidates,
            confidence: p1,
        };
    }
    match picked {
        Some(key) => JevVerdict::Route {
            channel: key.channel.clone(),
            addressee: key.app.clone(),
            confidence: p1,
            follow_up: false,
        },
        None => JevVerdict::Malformed(format!("pick `{pick}` left the option set")),
    }
}

/// A numbered ask waiting for its reply: the member's ORIGINAL message and
/// the channels the ask named (ids, with the labels the member read and the
/// app each pick addresses). Memory only, one queue per contact, expires —
/// message text never reaches disk or audit (D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub original_text: String,
    /// The channel ids, best first.
    pub candidates: Vec<String>,
    /// The labels the numbered list showed, parallel to `candidates`.
    pub labels: Vec<String>,
    /// The app each candidate addresses when picked (parallel; `None` = the
    /// channel's default app).
    pub addressees: Vec<Option<String>>,
    /// When the ask was made (a photo joins it only within
    /// [`PHOTO_BATCH_WINDOW_SECS`]).
    pub asked_at_secs: u64,
    pub expires_at_secs: u64,
    /// The photos or clips waiting with the ask — the asked turn's, plus any
    /// the member sent before answering (WeChat sends a multi-photo pick as
    /// one message per photo). Delivered with the answer. Memory only, like
    /// the text (D13).
    pub media: Vec<crate::media::InboundMedia>,
    /// The asked photo's description — what an app that takes no photos
    /// receives instead of it. Memory only.
    pub description: Option<String>,
}

impl PendingAsk {
    /// The app the ask's `i`-th candidate addresses.
    pub fn addressee_of(&self, channel: &str) -> Option<String> {
        self.candidates
            .iter()
            .position(|c| c == channel)
            .and_then(|i| self.addressees.get(i).cloned().flatten())
    }
}

/// #722 — how soon after an ask a further photo counts as the same send.
/// WeChat delivers a multi-photo pick as one message per photo; a photo that
/// arrives later is a new turn and routes on its own (unmeasured: a minute is
/// a guess at "the same send", not a measured WeChat interval).
pub const PHOTO_BATCH_WINDOW_SECS: u64 = 60;

/// Whether a further photo joins this ask's held batch: the ask is live,
/// already holds media, and was made within the batch window.
pub fn joins_photo_batch(ask: &PendingAsk, now_secs: u64) -> bool {
    ask.expires_at_secs >= now_secs
        && !ask.media.is_empty()
        && now_secs.saturating_sub(ask.asked_at_secs) <= PHOTO_BATCH_WINDOW_SECS
}

/// #722 — what a photo is routed by: one line from the stack's vision model.
/// Measured 2026-09-25 on the VE stack's chat endpoint (Doubao-Seed-2.0-mini)
/// with reasoning off: 1.0–1.6 s, ~1,400 tokens in, ~25 out; with reasoning
/// on, 4.5 s and ~480 out — hence `thinking: disabled`. `temperature: 0`
/// narrows the wording's spread (it does not make it repeatable). DeepSeek
/// V4.1 Flash through Ark (2026-09-25): the same routing on every test photo,
/// identical wording run to run, ~919 tokens in per photo against ~1,377.
pub const DESCRIBE_PROMPT: &str = "这张照片是家里人发给家庭助手的。用一句中文说清楚照片拍的是什么：在哪里、有哪些主要东西（不超过40个字）。只写看得到的内容，不要推测用途，不要加前缀。";
pub const DESCRIBE_MAX_CHARS: usize = 120;

/// The chat body for a photo's description: the original as a data URI (its
/// real content type) + the prompt, on `model` — or, with none, on the
/// stack's own chat endpoint (the gate fills it in).
pub fn describe_request(media: &crate::media::InboundMedia, model: Option<&str>) -> Value {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let ct = if media.content_type.trim().is_empty() {
        "image/jpeg"
    } else {
        media.content_type.trim()
    };
    let mut body = json!({
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image_url",
                  "image_url": { "url": format!("data:{ct};base64,{}", STANDARD.encode(&media.bytes)) } },
                { "type": "text", "text": DESCRIBE_PROMPT }
            ]
        }],
        "max_tokens": 120,
        "temperature": 0,
        "stream": false,
        "thinking": { "type": "disabled" }
    });
    if let Some(m) = model.map(str::trim).filter(|m| !m.is_empty()) {
        body["model"] = Value::String(m.to_string());
    }
    body
}

/// What the router is handed for a photo: its description, with the member's
/// caption first when there is one (Telegram).
pub fn photo_message(caption: &str, description: &str) -> String {
    if caption.trim().is_empty() {
        format!("[the member sent a photo] {description}")
    } else {
        format!("{} [with a photo: {description}]", caption.trim())
    }
}

/// What an app that takes no photos receives instead of one.
pub fn photo_as_text(caption: &str, description: &str) -> String {
    if caption.trim().is_empty() {
        format!("[照片] {description}")
    } else {
        format!("{}\n[照片] {description}", caption.trim())
    }
}

/// What the member's next message means for their waiting asks — a queue,
/// oldest first: an answer resolves the OLDEST ask, a new message never
/// cancels one (owner, 2026-09-26: "the first will be interrupted").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskReply {
    /// No ask is waiting.
    NoAsk,
    /// It answers the oldest ask: the chosen channel (and the app the pick
    /// addresses there), that ask's ORIGINAL message and the photos or clips
    /// that waited with it. `next` is the question now at the head of the
    /// queue (its labels), when another waits.
    Answered {
        channel: String,
        addressee: Option<String>,
        original_text: String,
        media: Vec<crate::media::InboundMedia>,
        description: Option<String>,
        next: Option<Vec<String>>,
    },
    /// The member called the oldest ask off («算了», «取消»): its message and
    /// media are dropped; `next` as above.
    Cancelled {
        released_media: usize,
        next: Option<Vec<String>>,
    },
    /// Asks are waiting and this is a new message: it routes on its own, with
    /// no follow-up anchor (the member's earlier message has not reached an
    /// app yet). `oldest` is the question still waiting (its labels).
    Waiting { oldest: Vec<String> },
}

/// Asks that ran out unanswered before this message: their messages were never
/// delivered, and the photos or clips they held are released.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredAsks {
    pub messages: usize,
    pub media: usize,
}

/// Words that call the oldest waiting ask off.
pub fn is_cancel(text: &str) -> bool {
    matches!(
        text.trim().to_lowercase().as_str(),
        "算了" | "取消" | "不用了" | "cancel" | "never mind"
    )
}

/// The reminder a new message's reply carries while an older question waits.
pub fn waiting_note(oldest: &[String], en: bool) -> String {
    if en {
        format!(
            "\n(Still waiting for your choice: {})",
            ask_text(oldest, true)
        )
    } else {
        format!("\n（上一条消息还在等你选择：{}）", ask_text(oldest, false))
    }
}

/// This message was asked back behind an older question: the reply asks the
/// older one (answers resolve the oldest first) and says this one waits.
pub fn queued_note(en: bool) -> &'static str {
    if en {
        " (your new message waits behind it — you'll be asked next)"
    } else {
        "（你刚发的这条排在后面，回答完再问你）"
    }
}

/// The question that comes up once the oldest one is answered or called off.
pub fn next_note(next: &[String], en: bool) -> String {
    if en {
        format!("\nNext: {}", ask_text(next, true))
    } else {
        format!("\n下一个问题：{}", ask_text(next, false))
    }
}

pub fn cancelled_text(en: bool) -> &'static str {
    if en {
        "OK — that earlier message was not passed on."
    } else {
        "好的，上一条消息不转达了。"
    }
}

/// Messages whose asks ran out: they were never delivered.
pub fn expired_note(messages: usize, en: bool) -> String {
    if en {
        format!("\n({messages} earlier message(s) waited too long for your choice and were not passed on — send them again if you need to)")
    } else {
        format!("\n（有 {messages} 条消息等你选择超时，没有转达，需要的话请重新发送）")
    }
}

/// Which candidate a reply picks: a number (`1`, `２`), a candidate's id, or
/// the label the member read — anything else is a new message, not an
/// answer. Returns the index into `candidates`.
pub fn parse_ask_reply(text: &str, candidates: &[String], labels: &[String]) -> Option<usize> {
    let t = text.trim();
    if t.is_empty() || candidates.is_empty() {
        return None;
    }
    let digits: String = t
        .chars()
        .map(|c| match c {
            '０'..='９' => char::from_u32(c as u32 - '０' as u32 + '0' as u32).unwrap_or(c),
            _ => c,
        })
        .collect();
    if let Ok(n) = digits.parse::<usize>() {
        return (1..=candidates.len()).contains(&n).then(|| n - 1);
    }
    let name = t.trim_start_matches('/').trim().to_lowercase();
    candidates
        .iter()
        .position(|c| c.to_lowercase() == name)
        .or_else(|| labels.iter().position(|l| l.trim().to_lowercase() == name))
}

/// The ask the member reads. Names THEIR channels, numbered.
pub fn ask_text(labels: &[String], en: bool) -> String {
    if labels.is_empty() {
        return crate::relay::ask_back_text(&[], en);
    }
    let numbered: Vec<String> = labels
        .iter()
        .enumerate()
        .map(|(i, a)| format!("{} {a}", i + 1))
        .collect();
    let numbers: Vec<String> = (1..=labels.len()).map(|n| n.to_string()).collect();
    if en {
        format!(
            "Which channel did you mean: {}? Reply with the number ({}).",
            numbered.join(" or "),
            numbers.join(" / "),
        )
    } else {
        format!(
            "你是想发到 {}？回复 {}。",
            numbered.join(" 还是 "),
            numbers.join(" 或 "),
        )
    }
}

/// Why a model call produced no verdict — every variant falls back to the
/// deterministic tier; the variant only shapes the log line.
#[derive(Debug, thiserror::Error)]
pub enum JevError {
    /// The gate has no typesafe family (503) — expected until the key lands.
    #[error("model gate has no decision model configured (503)")]
    Unconfigured,
    /// The gate refused the call (401 key, 429 budget / vendor rate limit, …).
    #[error("model gate answered HTTP {0}: {1}")]
    Status(u16, String),
    #[error("model gate unreachable: {0}")]
    Transport(String),
    #[error("model gate answer unusable: {0}")]
    Malformed(String),
}

/// The contact gate's client for the model gate: `/v1/systemone` (the
/// decision) and `/v1/chat/completions` (a photo's description).
pub struct JevClient {
    http: reqwest::Client,
    url: String,
    chat_url: String,
    models_url: String,
    key: String,
}

impl JevClient {
    pub fn new(gate_url: &str, key: &str, timeout_ms: u64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms.max(100)))
            .build()
            .unwrap_or_default();
        let base = gate_url.trim_end_matches('/');
        Self {
            http,
            url: format!("{base}{SYSTEMONE_ROUTE}"),
            chat_url: format!("{base}/v1/chat/completions"),
            models_url: format!("{base}/v1/systemone/models"),
            key: key.to_string(),
        }
    }

    /// The decision model's server as the model gate reports it (its base URL
    /// and `/v1/models`), or `{ "error": … }` — for the router view, never a turn.
    pub async fn upstream_info(&self) -> Value {
        let resp = match self
            .http
            .get(&self.models_url)
            .timeout(Duration::from_secs(3))
            .bearer_auth(&self.key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => return json!({ "error": e.to_string() }),
        };
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            body
        } else {
            json!({ "error": format!("model gate HTTP {status}"), "detail": body })
        }
    }

    /// Describe a photo in one short line, through the model gate's chat relay
    /// on the stack's own chat model (the gate fills it in).
    pub async fn describe(
        &self,
        media: &crate::media::InboundMedia,
        model: Option<&str>,
        timeout_ms: u64,
    ) -> Result<String, JevError> {
        let resp = self
            .http
            .post(&self.chat_url)
            .timeout(Duration::from_millis(timeout_ms.max(100)))
            .bearer_auth(&self.key)
            .json(&describe_request(media, model))
            .send()
            .await
            .map_err(|e| JevError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body: Value = resp
            .json()
            .await
            .map_err(|e| JevError::Malformed(e.to_string()))?;
        if !(200..300).contains(&status) {
            let detail: String = body.to_string().chars().take(200).collect();
            return Err(JevError::Status(status, detail));
        }
        let text: String = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .chars()
            .take(DESCRIBE_MAX_CHARS)
            .collect();
        if text.is_empty() {
            return Err(JevError::Malformed("empty description".into()));
        }
        Ok(text)
    }

    pub async fn decide(&self, req: &SystemOneRequest) -> Result<SystemOneResponse, JevError> {
        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(&self.key)
            .json(req)
            .send()
            .await
            .map_err(|e| JevError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| JevError::Transport(e.to_string()))?;
        if status == 503 {
            return Err(JevError::Unconfigured);
        }
        if !(200..300).contains(&status) {
            let detail = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]).to_string();
            return Err(JevError::Status(status, detail));
        }
        serde_json::from_slice(&bytes).map_err(|e| JevError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_protocol::{
        ChannelApp, Contact, ContactRegistry, SystemOneAnswer, SystemOneUsage,
    };

    fn registry() -> ContactRegistry {
        let mut reg = ContactRegistry::default();
        for (id, name, tier, tid) in [
            ("c-mama", "妈妈", ContactTier::Owner, "o1"),
            ("c-baba", "爸爸", ContactTier::Partner, "o2"),
            ("c-xm", "小明", ContactTier::Kid, "o3"),
        ] {
            reg.bound.push(Contact {
                contact_id: id.into(),
                transport: "weixin".into(),
                transport_id: tid.into(),
                display_name: name.into(),
                tier,
                legacy_reach: vec![],
                welcomed: true,
            });
        }
        let family = reg.channel_or_new("family-chat");
        family.name = "家庭群".into();
        family.purpose = "家里的日常：吃什么、饭菜的照片".into();
        family.household_default = true;
        family.upsert_app(ChannelApp {
            alias: "chef".into(),
            slot: "family_chat".into(),
            description: "饭菜和冰箱的照片从这里发来；计划与回复也从这里回去。".into(),
            takes: vec![ChannelEventKind::Text, ChannelEventKind::Image],
            audience: vec![],
        });
        family.upsert_app(ChannelApp {
            alias: "storyteller".into(),
            slot: "story_chat".into(),
            description: "应要求讲个故事".into(),
            takes: vec![ChannelEventKind::Text],
            audience: vec![],
        });
        family.set_member("c-mama", true, true);
        family.set_member("c-baba", true, true);
        family.set_member("c-xm", false, true);
        family.updated_at = 5;
        let op = reg.channel_or_new("opchat-chef");
        op.name = "chef·操作".into();
        op.operator_of = Some("chef".into());
        op.purpose = "对 chef 本身的指令：设置、批准".into();
        op.upsert_app(ChannelApp {
            alias: "chef".into(),
            slot: "opchat".into(),
            description: "接收操作者的指令".into(),
            takes: vec![],
            audience: vec![],
        });
        op.set_member("c-mama", true, true);
        reg
    }

    fn options() -> Vec<ChannelOption> {
        channel_options(&registry(), "c-mama")
    }

    fn keys(o: &[ChannelOption]) -> Vec<OptionKey> {
        option_keys(o)
    }

    fn response(choice: &str, probs: &[(&str, f64)], confidence: f64) -> SystemOneResponse {
        let mut answers = BTreeMap::new();
        answers.insert(
            DESTINATION_QUESTION.to_string(),
            SystemOneAnswer::Choice {
                choice: choice.into(),
                probabilities: probs.iter().map(|(k, p)| (k.to_string(), *p)).collect(),
                confidence,
            },
        );
        SystemOneResponse {
            model: "jev-1.13.0".into(),
            answers,
            usage: SystemOneUsage {
                input_tokens: 300,
                output_tokens: 20,
            },
        }
    }

    fn with_continues(mut r: SystemOneResponse, noul: f64) -> SystemOneResponse {
        r.answers.insert(
            CONTINUES_QUESTION.to_string(),
            SystemOneAnswer::Noul { noul },
        );
        r
    }

    #[test]
    fn an_option_is_rendered_from_the_document_alone() {
        let o = options();
        assert_eq!(
            keys(&o).iter().map(|k| k.key.clone()).collect::<Vec<_>>(),
            vec!["family-chat/chef", "family-chat/storyteller", "opchat-chef"],
            "household first; one row per app on a shared channel"
        );
        assert_eq!(
            o[0].line,
            "家庭群：家里的日常：吃什么、饭菜的照片。在这里：chef（饭菜和冰箱的照片从这里发来；计划与回复也从这里回去）；storyteller（应要求讲个故事）。成员：你、爸爸（配偶）；小明（孩子）只看。"
        );
        assert_eq!(
            o[1].line,
            "chef·操作（chef 的操作频道）：对 chef 本身的指令：设置、批准。在这里：chef（接收操作者的指令）。成员：只有你。"
        );
        assert_eq!(
            o[0].row_line("storyteller"),
            "家庭群：家里的日常：吃什么、饭菜的照片。这条给 storyteller（应要求讲个故事）。也在这里：chef。成员：你、爸爸（配偶）；小明（孩子）只看。"
        );
        assert_eq!(o[0].members, vec!["爸爸（配偶）", "小明（孩子）"]);
        assert_eq!(o[0].default_app(Some("chef")).as_deref(), Some("chef"));
        assert_eq!(o[1].default_app(None).as_deref(), Some("chef"));
        assert!(o[0].takes("chef", ChannelEventKind::Image));
        assert!(!o[0].takes("storyteller", ChannelEventKind::Image));
        assert!(
            o[1].takes("chef", ChannelEventKind::AudioClip),
            "undeclared takes all"
        );
        // A member who only reads has no options.
        assert!(channel_options(&registry(), "c-xm").is_empty());
    }

    #[test]
    fn the_destination_sees_the_message_only_and_the_last_channel_rides_in_its_own_question() {
        let o = options();
        let req = build_request(
            "jev-1.13.0",
            "讲个故事",
            "妈妈",
            "owner",
            Some("family-chat"),
            &o,
        );
        let SystemOneQuestion::Choice {
            criteria,
            instructions,
        } = &req.questions[DESTINATION_QUESTION]
        else {
            panic!("destination must be a choice");
        };
        let keys: Vec<&String> = criteria.keys().collect();
        assert_eq!(
            keys,
            vec![
                "family-chat/chef",
                "family-chat/storyteller",
                "opchat-chef",
                "unclear"
            ]
        );
        assert_eq!(criteria["family-chat/chef"], o[0].row_line("chef"));
        assert_eq!(criteria["opchat-chef"], o[1].line);
        assert_eq!(req.state["message"], "讲个故事");
        assert_eq!(req.state["sender"], "妈妈");
        assert!(req.state.get("last_channel").is_none());
        assert!(!instructions.as_str().unwrap().contains("last_channel"));
        let SystemOneQuestion::Noul {
            instructions,
            criteria,
        } = &req.questions[CONTINUES_QUESTION]
        else {
            panic!("continues must be a noul");
        };
        assert_eq!(instructions["last_channel"], "家庭群");
        assert!(criteria.as_ref().unwrap().yes.is_some());
        assert_eq!(req.questions.len(), 2);
        // No last channel → no follow-up question; an unknown one too.
        let req = build_request("jev-1.13.0", "hi", "妈妈", "owner", None, &o);
        assert!(!req.questions.contains_key(CONTINUES_QUESTION));
        let req = build_request("jev-1.13.0", "hi", "妈妈", "owner", Some("gone"), &o);
        assert!(!req.questions.contains_key(CONTINUES_QUESTION));
    }

    #[test]
    fn a_photo_is_described_by_the_stacks_model_and_routed_as_a_line() {
        let media = crate::media::InboundMedia {
            kind: agentkeys_protocol::ChannelEventKind::Image,
            content_type: String::new(),
            bytes: vec![1, 2, 3],
        };
        let body = describe_request(&media, None);
        assert!(body.get("model").is_none(), "the gate names the model");
        assert_eq!(
            describe_request(&media, Some("deepseek-v4-1-flash-260910"))["model"],
            "deepseek-v4-1-flash-260910"
        );
        assert_eq!(body["thinking"]["type"], "disabled");
        assert_eq!(body["temperature"], 0);
        assert_eq!(
            body["messages"][0]["content"][0]["image_url"]["url"],
            "data:image/jpeg;base64,AQID"
        );
        assert_eq!(body["messages"][0]["content"][1]["text"], DESCRIBE_PROMPT);
        assert_eq!(
            photo_message("", "冰箱里有鸡蛋"),
            "[the member sent a photo] 冰箱里有鸡蛋"
        );
        assert_eq!(
            photo_message(" 还能吃吗 ", "冰箱里有鸡蛋"),
            "还能吃吗 [with a photo: 冰箱里有鸡蛋]"
        );
        assert_eq!(photo_as_text("", "门口有个纸箱"), "[照片] 门口有个纸箱");
        assert_eq!(
            photo_as_text("到了吗", "门口有个纸箱"),
            "到了吗\n[照片] 门口有个纸箱"
        );
    }

    #[test]
    fn a_photo_joins_an_ask_only_while_the_send_is_still_going() {
        let photo = crate::media::InboundMedia {
            kind: agentkeys_protocol::ChannelEventKind::Image,
            content_type: "image/jpeg".into(),
            bytes: vec![1],
        };
        let ask = PendingAsk {
            original_text: String::new(),
            candidates: vec!["family-chat".into()],
            labels: vec!["家庭群".into()],
            addressees: vec![None],
            asked_at_secs: 1000,
            expires_at_secs: 1600,
            media: vec![photo],
            description: None,
        };
        assert!(joins_photo_batch(&ask, 1000 + PHOTO_BATCH_WINDOW_SECS));
        assert!(!joins_photo_batch(&ask, 1001 + PHOTO_BATCH_WINDOW_SECS));
        let text_ask = PendingAsk {
            media: Vec::new(),
            ..ask.clone()
        };
        assert!(
            !joins_photo_batch(&text_ask, 1001),
            "a text ask holds no batch"
        );
        assert!(
            !joins_photo_batch(&ask, 1601),
            "an expired ask holds nothing"
        );
        assert_eq!(ask.addressee_of("family-chat"), None);
    }

    #[test]
    fn a_majority_pick_routes_and_anything_less_asks_with_ranked_candidates() {
        let o = keys(&options());
        let r = response(
            "family-chat/storyteller",
            &[
                ("family-chat/storyteller", 0.9),
                ("family-chat/chef", 0.05),
                ("opchat-chef", 0.03),
                ("unclear", 0.02),
            ],
            0.85,
        );
        assert_eq!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Route {
                channel: "family-chat".into(),
                addressee: Some("storyteller".into()),
                confidence: 0.9,
                follow_up: false,
            }
        );
        // 0.45 < 0.5 → ask, candidate CHANNELS best first, deduped, `unclear`
        // never among them.
        let r = response(
            "opchat-chef",
            &[
                ("family-chat/chef", 0.40),
                ("opchat-chef", 0.45),
                ("family-chat/storyteller", 0.05),
                ("unclear", 0.10),
            ],
            0.2,
        );
        match verdict_from(&r, &o, 0.5, None, 0.7) {
            JevVerdict::Ask {
                candidates,
                confidence,
            } => {
                assert_eq!(candidates, vec!["opchat-chef", "family-chat"]);
                assert!((confidence - 0.45).abs() < 1e-9);
            }
            other => panic!("expected an ask, got {other:?}"),
        }
        // `unclear` on top asks even with a high probability.
        let r = response(
            "unclear",
            &[
                ("family-chat/chef", 0.1),
                ("opchat-chef", 0.1),
                ("unclear", 0.8),
            ],
            0.7,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Ask { .. }
        ));
        // An exact tie never routes on a coin flip.
        let r = response(
            "family-chat/chef",
            &[("family-chat/chef", 0.5), ("opchat-chef", 0.5)],
            0.0,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Ask { .. }
        ));
    }

    #[test]
    fn an_answer_outside_the_options_is_malformed_never_a_route() {
        let o = keys(&options());
        let r = response(
            "admin-room",
            &[("admin-room", 0.99), ("family-chat/chef", 0.01)],
            0.99,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Malformed(_)
        ));
        // A bare channel key for a SHARED channel was never offered either.
        let r = response(
            "family-chat",
            &[("family-chat", 0.9), ("opchat-chef", 0.1)],
            0.9,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Malformed(_)
        ));
        let r = response(
            "family-chat/chef",
            &[("family-chat/chef", 0.5), ("vault", 0.5)],
            0.9,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Malformed(_)
        ));
        let mut r = response("family-chat/chef", &[("family-chat/chef", 1.0)], 1.0);
        r.answers.clear();
        assert!(matches!(
            verdict_from(&r, &o, 0.5, None, 0.7),
            JevVerdict::Malformed(_)
        ));
    }

    #[test]
    fn a_follow_up_stays_on_the_last_channel_a_new_request_goes_where_it_points() {
        let o = keys(&options());
        let r = with_continues(
            response(
                "unclear",
                &[
                    ("family-chat/chef", 0.35),
                    ("opchat-chef", 0.10),
                    ("unclear", 0.55),
                ],
                0.3,
            ),
            0.93,
        );
        assert_eq!(
            verdict_from(&r, &o, 0.5, Some("family-chat"), 0.7),
            JevVerdict::Route {
                channel: "family-chat".into(),
                addressee: None,
                confidence: 0.93,
                follow_up: true,
            }
        );
        // A clear pick on the same channel is not "elsewhere": the follow-up
        // still holds (the previous turn's app keeps the conversation).
        let r = with_continues(
            response(
                "family-chat/storyteller",
                &[
                    ("family-chat/storyteller", 0.9),
                    ("family-chat/chef", 0.05),
                    ("unclear", 0.05),
                ],
                0.9,
            ),
            0.9,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, Some("family-chat"), 0.7),
            JevVerdict::Route { channel, follow_up: true, .. } if channel == "family-chat"
        ));
        // A clear destination elsewhere wins even if the follow-up were fooled.
        let r = with_continues(
            response(
                "opchat-chef",
                &[
                    ("family-chat/chef", 0.01),
                    ("opchat-chef", 0.98),
                    ("unclear", 0.01),
                ],
                0.97,
            ),
            0.9,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, Some("family-chat"), 0.7),
            JevVerdict::Route { channel, follow_up: false, .. } if channel == "opchat-chef"
        ));
        // A new request after another conversation (continues 0.45): the
        // destination decides — unsure, so ask, never the previous channel.
        let r = with_continues(
            response(
                "family-chat/chef",
                &[
                    ("family-chat/chef", 0.40),
                    ("opchat-chef", 0.25),
                    ("unclear", 0.35),
                ],
                0.1,
            ),
            0.45,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, Some("opchat-chef"), 0.7),
            JevVerdict::Ask { .. }
        ));
        // A last channel no longer an option is never stuck to; a missing
        // `continues` answer counts as "not a follow-up".
        let r = with_continues(
            response(
                "unclear",
                &[("family-chat/chef", 0.3), ("unclear", 0.7)],
                0.4,
            ),
            0.99,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, Some("gone"), 0.7),
            JevVerdict::Ask { .. }
        ));
        let r = response(
            "unclear",
            &[("family-chat/chef", 0.3), ("unclear", 0.7)],
            0.4,
        );
        assert!(matches!(
            verdict_from(&r, &o, 0.5, Some("family-chat"), 0.7),
            JevVerdict::Ask { .. }
        ));
    }

    #[test]
    fn a_shared_channel_is_one_row_per_app_and_a_single_app_channel_is_itself() {
        let k = keys(&options());
        assert_eq!(k[0].channel, "family-chat");
        assert_eq!(k[0].app.as_deref(), Some("chef"));
        assert_eq!(k[1].app.as_deref(), Some("storyteller"));
        assert_eq!(k[2].key, "opchat-chef");
        assert_eq!(k[2].app, None);
    }

    #[test]
    fn ask_replies_pick_by_number_id_or_label_and_anything_else_is_a_new_message() {
        let c = vec!["family-chat".to_string(), "opchat-chef".to_string()];
        let l = vec!["家庭群".to_string(), "chef·操作".to_string()];
        assert_eq!(parse_ask_reply("1", &c, &l), Some(0));
        assert_eq!(parse_ask_reply(" ２ ", &c, &l), Some(1));
        assert_eq!(parse_ask_reply("家庭群", &c, &l), Some(0));
        assert_eq!(parse_ask_reply("opchat-chef", &c, &l), Some(1));
        assert_eq!(parse_ask_reply("3", &c, &l), None);
        assert_eq!(parse_ask_reply("0", &c, &l), None);
        assert_eq!(parse_ask_reply("今晚吃什么", &c, &l), None);
        assert_eq!(parse_ask_reply("1", &[], &[]), None);
    }

    #[test]
    fn ask_text_names_the_channels_numbered_in_both_languages() {
        let l = vec!["家庭群".to_string(), "chef·操作".to_string()];
        assert_eq!(
            ask_text(&l, false),
            "你是想发到 1 家庭群 还是 2 chef·操作？回复 1 或 2。"
        );
        assert_eq!(
            ask_text(&l, true),
            "Which channel did you mean: 1 家庭群 or 2 chef·操作? Reply with the number (1 / 2)."
        );
        assert!(ask_text(&[], false).contains("频道"));
    }

    #[test]
    fn engine_auto_needs_both_gate_coordinates() {
        let mut cfg = RouterConfig::default();
        assert!(!cfg.jev_active());
        cfg.gate_url = Some("http://127.0.0.1:8077".into());
        assert!(!cfg.jev_active());
        cfg.gate_key = Some("gk_x".into());
        assert!(cfg.jev_active());
        cfg.engine = RouterEngine::Deterministic;
        assert!(!cfg.jev_active());
        assert_eq!(
            RouterEngine::parse("off"),
            Some(RouterEngine::Deterministic)
        );
        assert_eq!(RouterEngine::parse("bogus"), None);
    }
}
