//! The daemon-ADVERTISED actions of this delegate (2026-09-24 — plan
//! `docs/plan/dsh-plugin-abstraction.md` PR 1): the verbs the dsh suite
//! registers as tools from `GET /v1/sandbox/self/actions`, and the ONE
//! publish core behind both `agentkeys-daemon --publish-once` and
//! `POST /v1/sandbox/self/publish`. The daemon is the one owner of "which
//! slots may this delegate publish to" (the spawn's bound channels, the live
//! rebind override) and "which namespace does it propose into by default" —
//! the suite used to re-derive both from env in TypeScript.
//!
//! Authority is unchanged: every publish mints the delegate's own
//! `channel-pub` cap (an ungranted feed is refused at cap-mint with the
//! worker's reason, never by a local rule); the advertised list only shapes
//! what the model sees.

use std::sync::Arc;

use agentkeys_backend_client::protocol::sandbox_actions::{
    advertised_actions, SandboxAction, OPCHAT_SLOT_NAME,
};
use agentkeys_backend_client::protocol::{ChannelEventKind, CARD_CONTENT_TYPE};

use crate::app_runtime::AppRuntimeConfig;
use crate::chat_loop::{ChatLoopConfig, DelegateCredential, Publisher, SessionHandle};

/// The slot NAMES this delegate may publish to: every bound `pub` / `duplex`
/// slot in binding order, then `opchat` (always a valid target — the daemon
/// resolves it to the operator-chat feed). Pure.
pub fn publish_slots(app: &AppRuntimeConfig) -> Vec<String> {
    let mut slots: Vec<String> = Vec::new();
    for b in &app.bound_channels {
        if b.slot.is_empty() || !b.direction.writes() || slots.contains(&b.slot) {
            continue;
        }
        slots.push(b.slot.clone());
    }
    if !slots.iter().any(|s| s == OPCHAT_SLOT_NAME) {
        slots.push(OPCHAT_SLOT_NAME.to_string());
    }
    slots
}

/// The advertised list for this env: the two verbs over the publishable
/// slots and the propose default (`None` = none derivable — the description
/// then carries no default note and the daemon refuses a namespace-less
/// proposal at push time).
pub fn advertised_for(app: &AppRuntimeConfig, own_namespace: Option<&str>) -> Vec<SandboxAction> {
    advertised_actions(&publish_slots(app), own_namespace)
}

/// One publish as requested (the route body or the `--publish-*` flags).
pub struct PublishInput {
    pub slot: String,
    /// Wire kind; blank = `text`.
    pub kind: String,
    pub bytes: Vec<u8>,
    pub correlation: Option<String>,
    pub content_type: Option<String>,
}

/// The card contract in one line — what a refused `doc` publish tells the app.
pub(crate) const CARD_CONTRACT_HINT: &str = "The card contract (schema 1): {\"card\": 1, \"title\": \"…\", \"title_zh\": \"…\", \"subtitle\": \"…\", \"metrics\": [{\"label\", \"label_zh\", \"value\", \"unit\"?, \"progress\"?}], \"sections\": [{\"title\", \"title_zh\", \"items\": [{\"text\", \"text_zh\"?, \"detail\"?}]}], \"alerts\": [{\"level\": \"info\"|\"warn\"|\"danger\", \"text\", \"text_zh\"?}], \"actions\": [{\"id\", \"label\", \"label_zh\", \"command\"}]} — every section item is {\"text\": …}, never {\"name\": …}; fix the JSON and publish again.";

/// #670 — a `doc` IS a card by contract. Validate it where the tool can tell
/// the app what is wrong, instead of letting a malformed document land on the
/// screen's feed: the renderer keeps the last real card and the console counts
/// "newer, not a card" (chef, 2026-09-27: 23 documents without `card: 1`,
/// items as `{name, time, duration}`). Other kinds pass.
pub(crate) fn validate_doc_body(kind: &str, bytes: &[u8]) -> Result<(), String> {
    if kind != "doc" {
        return Ok(());
    }
    agentkeys_backend_client::protocol::parse_card(bytes)
        .map(|_| ())
        .map_err(|reason| {
            format!("publish: the doc is not a card — {reason}. {CARD_CONTRACT_HINT}")
        })
}

/// The media type a kind implies when the caller names none.
pub fn default_content_type(kind: &str) -> String {
    match kind {
        "image" | "frame" => "image/jpeg".to_string(),
        "audio-clip" => "audio/wav".to_string(),
        "doc" => CARD_CONTENT_TYPE.to_string(),
        _ => "text/plain".to_string(),
    }
}

/// The inline ceiling above which a body rides by reference (#667).
pub fn inline_max_bytes(lookup: impl Fn(&str) -> Option<String>) -> usize {
    lookup("AGENTKEYS_CHANNEL_INLINE_MAX_BYTES")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1 << 20)
}

/// Validate + publish ONE event as the delegate: resolve the slot against the
/// bound channels (opchat always resolves; an unknown name is treated as a
/// raw channel id the worker will judge), mint the publish cap, publish
/// `direction: out`. Returns the receipt the one-shot prints and the route
/// answers — `summary` is the line the tool renders.
pub async fn publish_once(
    cfg: Arc<ChatLoopConfig>,
    credential: Arc<DelegateCredential>,
    bearer: Option<String>,
    input: PublishInput,
) -> anyhow::Result<serde_json::Value> {
    let slot = input.slot.trim().to_string();
    if slot.is_empty() {
        anyhow::bail!("publish: a slot name (or channel id) is required");
    }
    let kind = {
        let k = input.kind.trim();
        if k.is_empty() {
            "text".to_string()
        } else {
            k.to_string()
        }
    };
    if ChannelEventKind::parse(&kind).is_none() {
        anyhow::bail!(
            "publish: kind must be one of text|image|audio-clip|frame|command|doc (got `{kind}`)"
        );
    }
    if input.bytes.is_empty() {
        anyhow::bail!("publish: the body is empty — nothing to publish");
    }
    validate_doc_body(&kind, &input.bytes).map_err(|e| anyhow::anyhow!("{e}"))?;
    let app = AppRuntimeConfig::from_env();
    let channel_id = app.resolve_publish_target(&slot, &cfg.chat_channel_id);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let session = Arc::new(match bearer {
        Some(b) => SessionHandle::with_bearer(http.clone(), cfg.clone(), credential, b),
        None => SessionHandle::new(http.clone(), cfg.clone(), credential),
    });
    let publisher = Publisher::new(http, cfg, session);
    let correlation = input
        .correlation
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| {
            format!(
                "publish-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            )
        });
    let content_type = input
        .content_type
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| default_content_type(&kind));
    let inline_max = inline_max_bytes(|k| std::env::var(k).ok());
    let body_ref = publisher
        .publish_bytes(
            &channel_id,
            &kind,
            &input.bytes,
            &content_type,
            &correlation,
            inline_max,
        )
        .await
        .map_err(|e| anyhow::anyhow!("publish: {e}"))?;
    let bytes = input.bytes.len();
    crate::chat_loop::note_tool_publish(&channel_id, &kind);
    Ok(serde_json::json!({
        "outcome": "published",
        "slot": slot,
        "channel_id": channel_id,
        "kind": kind,
        "bytes": bytes,
        "correlation": correlation,
        "body_ref": body_ref,
        "summary": format!("published: {kind} → {slot} ({channel_id}), {bytes} bytes, correlation {correlation}"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_backend_client::protocol::sandbox_actions::{PROPOSE_ACTION, PUBLISH_ACTION};

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(kk, _)| *kk == k)
                .map(|(_, v)| v.to_string())
        }
    }

    /// The document chef improvised (no `card: 1`, `{name, time, duration}`
    /// items) is refused with the contract; a real card and a text pass.
    #[test]
    fn a_doc_that_is_not_a_card_is_refused_with_the_contract() {
        let improvised = r#"{"title": "家庭厨师 · 今天", "subtitle": "09-27 · 今日暂未记录餐食", "metrics": [], "sections": [{"title": "下一餐", "items": [{"name": "炒面筋配时蔬", "time": "今晚"}]}]}"#.as_bytes();
        let err = validate_doc_body("doc", improvised).unwrap_err();
        assert!(err.contains("not a card"), "{err}");
        assert!(err.contains("\"card\": 1"), "{err}");
        let card = r#"{"card": 1, "title": "Chef · today", "title_zh": "家庭厨师 · 今天", "sections": [{"title": "Next meal", "items": [{"text": "炒面筋配时蔬", "detail": "今晚 · 30分钟"}]}]}"#.as_bytes();
        assert!(validate_doc_body("doc", card).is_ok());
        assert!(validate_doc_body("text", improvised).is_ok());
    }

    #[test]
    fn publishable_slots_are_the_writable_bindings_then_opchat() {
        let bound = serde_json::json!([
            {"slot": "kitchen_screen", "kind": "display", "direction": "pub", "channel_id": "kitchen-display"},
            {"slot": "family_chat", "kind": "messaging", "direction": "duplex", "channel_id": "weixin-chef"},
            {"slot": "doorway_camera", "kind": "camera", "direction": "sub", "channel_id": "cam-1"},
            {"slot": "kitchen_screen", "kind": "display", "direction": "pub", "channel_id": "kitchen-display-2"}
        ])
        .to_string();
        let app =
            AppRuntimeConfig::from_lookup(lookup(&[("AGENTKEYS_BOUND_CHANNELS", bound.as_str())]));
        assert_eq!(
            publish_slots(&app),
            vec!["kitchen_screen", "family_chat", "opchat"]
        );
        let bare = AppRuntimeConfig::from_lookup(lookup(&[]));
        assert_eq!(publish_slots(&bare), vec!["opchat"]);
    }

    #[test]
    fn the_advertised_list_names_the_slots_and_the_default_namespace() {
        let bound = serde_json::json!([
            {"slot": "kitchen_screen", "kind": "display", "direction": "pub", "channel_id": "kitchen-display"}
        ])
        .to_string();
        let app =
            AppRuntimeConfig::from_lookup(lookup(&[("AGENTKEYS_BOUND_CHANNELS", bound.as_str())]));
        let actions = advertised_for(&app, Some("app-chef"));
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].name, PUBLISH_ACTION);
        assert!(actions[0].description.contains("kitchen_screen, opchat"));
        assert_eq!(actions[1].name, PROPOSE_ACTION);
        assert!(actions[1]
            .description
            .contains("Your own namespace is app-chef"));
    }

    #[test]
    fn content_types_follow_the_kind_and_the_inline_ceiling_defaults() {
        assert_eq!(default_content_type("doc"), CARD_CONTENT_TYPE);
        assert_eq!(default_content_type("image"), "image/jpeg");
        assert_eq!(default_content_type("text"), "text/plain");
        assert_eq!(inline_max_bytes(lookup(&[])), 1 << 20);
        assert_eq!(
            inline_max_bytes(lookup(&[("AGENTKEYS_CHANNEL_INLINE_MAX_BYTES", "4096")])),
            4096
        );
        assert_eq!(
            inline_max_bytes(lookup(&[("AGENTKEYS_CHANNEL_INLINE_MAX_BYTES", "x")])),
            1 << 20
        );
    }
}
