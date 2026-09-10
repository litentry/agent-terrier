//! The **card contract** (#670, plan §4.9) — the framework's one device UI
//! DSL: a versioned, declarative, bilingual `card` document an application
//! publishes as a `doc` event into a `display` slot, rendered by dumb renderers
//! (the console's `CardView`, a device-mode web app, the LVGL firmware) that
//! publish the card's actions back as `command` events with their OWN device
//! actor. "Tap *swap dinner* on the phone" and "tap it on the kitchen screen"
//! are the same event on the same feed, attributed to different actors.
//!
//! ONE owner (D7): the schema lives here; ts-rs generates the frontend type;
//! the golden fixtures under `e2e/fixtures/cards/` are rendered by every
//! renderer's snapshot test.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The card schema version this crate reads and writes (F3-style additive
/// evolution: new fields default; a breaking change bumps this).
pub const CARD_SCHEMA: u32 = 1;

/// The `doc` event kind a card rides on (the ESP32's existing `doc` render is
/// the v0 renderer — it shows the title + sections as text).
pub const CARD_CONTENT_TYPE: &str = "application/vnd.agentkeys.card+json";

/// One headline number (eaten vs target, outings today, …).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardMetric {
    pub label: String,
    #[serde(default)]
    pub label_zh: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub unit: Option<String>,
    /// 0..=1 when the metric is a progress toward a target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub progress: Option<f32>,
}

/// One line of a section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardItem {
    pub text: String,
    #[serde(default)]
    pub text_zh: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub detail_zh: Option<String>,
    /// A short renderer-neutral tag (`done`, `low`, `new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub tag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardSection {
    pub title: String,
    #[serde(default)]
    pub title_zh: String,
    #[serde(default)]
    pub items: Vec<CardItem>,
}

/// An alert's severity — renderer maps to a color, never to a behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(rename_all = "lowercase")]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub enum CardAlertLevel {
    #[default]
    Info,
    Warn,
    Danger,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardAlert {
    #[serde(default)]
    pub level: CardAlertLevel,
    pub text: String,
    #[serde(default)]
    pub text_zh: String,
}

/// A tappable action. Tapping publishes a `command` event whose body is a
/// [`CardCommand`] — the renderer never interprets `command`/`args`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardAction {
    /// Stable within the card (`dinner.swap`).
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub label_zh: String,
    /// The command name the app's skills act on.
    pub command: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    #[ts(type = "unknown")]
    pub args: Value,
}

/// The card document — published as the `doc` event body (UTF-8 JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardDocument {
    /// Schema version — [`CARD_SCHEMA`].
    pub card: u32,
    pub title: String,
    #[serde(default)]
    pub title_zh: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub subtitle_zh: String,
    #[serde(default)]
    pub metrics: Vec<CardMetric>,
    #[serde(default)]
    pub sections: Vec<CardSection>,
    #[serde(default)]
    pub alerts: Vec<CardAlert>,
    #[serde(default)]
    pub actions: Vec<CardAction>,
    /// Unix seconds the app composed the card (a renderer shows staleness).
    #[serde(default)]
    #[ts(type = "number")]
    pub updated_at: u64,
}

impl CardDocument {
    pub fn new(title: impl Into<String>, updated_at: u64) -> Self {
        Self {
            card: CARD_SCHEMA,
            title: title.into(),
            title_zh: String::new(),
            subtitle: String::new(),
            subtitle_zh: String::new(),
            metrics: Vec::new(),
            sections: Vec::new(),
            alerts: Vec::new(),
            actions: Vec::new(),
            updated_at,
        }
    }

    /// The v0 text rendering (what a `doc`-only renderer such as the ESP32's
    /// existing path shows): title, metrics, sections, alerts as plain lines.
    pub fn to_plain_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.title);
        out.push('\n');
        if !self.subtitle.is_empty() {
            out.push_str(&self.subtitle);
            out.push('\n');
        }
        for m in &self.metrics {
            out.push_str(&format!(
                "{}: {}{}\n",
                m.label,
                m.value,
                m.unit
                    .as_deref()
                    .map(|u| format!(" {u}"))
                    .unwrap_or_default()
            ));
        }
        for s in &self.sections {
            out.push_str(&format!("[{}]\n", s.title));
            for it in &s.items {
                out.push_str(&format!("• {}", it.text));
                if let Some(d) = &it.detail {
                    out.push_str(&format!(" — {d}"));
                }
                out.push('\n');
            }
        }
        for a in &self.alerts {
            out.push_str(&format!("! {}\n", a.text));
        }
        out
    }
}

/// Parse a `doc` body as a card; `Err` names the reason (a renderer falls back
/// to the plain-text `doc` view).
pub fn parse_card(body: &[u8]) -> Result<CardDocument, String> {
    let card: CardDocument =
        serde_json::from_slice(body).map_err(|e| format!("not a card document: {e}"))?;
    if card.card == 0 || card.card > CARD_SCHEMA {
        return Err(format!(
            "card schema {} is not supported (this renderer reads ≤ {CARD_SCHEMA})",
            card.card
        ));
    }
    if card.title.trim().is_empty() {
        return Err("card has no title".into());
    }
    Ok(card)
}

/// The `command` event body a renderer publishes when an action is tapped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CardCommand {
    /// Schema version — [`CARD_SCHEMA`].
    pub card: u32,
    /// The tapped [`CardAction::id`].
    pub action: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    #[ts(type = "unknown")]
    pub args: Value,
    /// The `updated_at` of the card the tap was made on — the app can ignore a
    /// tap on a stale card.
    #[serde(default)]
    #[ts(type = "number")]
    pub card_updated_at: u64,
}

impl CardCommand {
    pub fn for_action(card: &CardDocument, action: &CardAction) -> Self {
        Self {
            card: CARD_SCHEMA,
            action: action.id.clone(),
            command: action.command.clone(),
            args: action.args.clone(),
            card_updated_at: card.updated_at,
        }
    }
}

/// Parse a `command` body as a card command (`Err` = not a card tap — e.g.
/// the device `jobs` command, which stays a bare string).
pub fn parse_card_command(body: &[u8]) -> Result<CardCommand, String> {
    let cmd: CardCommand =
        serde_json::from_slice(body).map_err(|e| format!("not a card command: {e}"))?;
    if cmd.action.trim().is_empty() || cmd.command.trim().is_empty() {
        return Err("card command needs an action id and a command".into());
    }
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CardDocument {
        let mut c = CardDocument::new("TODAY · 1,180 / 2,000 kcal", 1_757_400_000);
        c.title_zh = "今天 · 1,180 / 2,000 千卡".into();
        c.metrics.push(CardMetric {
            label: "eaten".into(),
            label_zh: "已吃".into(),
            value: "1180".into(),
            unit: Some("kcal".into()),
            progress: Some(0.59),
        });
        c.sections.push(CardSection {
            title: "Meals".into(),
            title_zh: "餐食".into(),
            items: vec![CardItem {
                text: "lunch · rice + chicken".into(),
                text_zh: "午餐 · 米饭 + 鸡肉".into(),
                detail: Some("≈ 650 kcal".into()),
                detail_zh: None,
                tag: None,
            }],
        });
        c.alerts.push(CardAlert {
            level: CardAlertLevel::Warn,
            text: "low on: eggs, milk".into(),
            text_zh: "不多了：鸡蛋、牛奶".into(),
        });
        c.actions.push(CardAction {
            id: "dinner.swap".into(),
            label: "Swap dinner".into(),
            label_zh: "换一个晚餐".into(),
            command: "dinner.swap".into(),
            args: serde_json::json!({ "reason": "tapped" }),
        });
        c
    }

    #[test]
    fn card_round_trips_and_parses() {
        let c = sample();
        let bytes = serde_json::to_vec(&c).unwrap();
        let back = parse_card(&bytes).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.card, CARD_SCHEMA);
    }

    #[test]
    fn parse_card_refuses_future_schema_and_untitled() {
        let mut c = sample();
        c.card = CARD_SCHEMA + 1;
        assert!(parse_card(&serde_json::to_vec(&c).unwrap()).is_err());
        let mut c = sample();
        c.title = "  ".into();
        assert!(parse_card(&serde_json::to_vec(&c).unwrap()).is_err());
        assert!(parse_card(b"plain text doc").is_err());
    }

    #[test]
    fn minimal_card_defaults_every_optional_field() {
        let c = parse_card(br#"{"card":1,"title":"Hi"}"#).unwrap();
        assert!(c.metrics.is_empty() && c.sections.is_empty() && c.actions.is_empty());
        assert_eq!(c.updated_at, 0);
    }

    #[test]
    fn command_body_carries_the_action_and_the_card_stamp() {
        let c = sample();
        let cmd = CardCommand::for_action(&c, &c.actions[0]);
        let bytes = serde_json::to_vec(&cmd).unwrap();
        let back = parse_card_command(&bytes).unwrap();
        assert_eq!(back.action, "dinner.swap");
        assert_eq!(back.command, "dinner.swap");
        assert_eq!(back.args["reason"], "tapped");
        assert_eq!(back.card_updated_at, 1_757_400_000);
        // The device `jobs` command is NOT a card command.
        assert!(parse_card_command(b"jobs").is_err());
    }

    #[test]
    fn plain_text_rendering_is_the_v0_doc_view() {
        let t = sample().to_plain_text();
        assert!(t.starts_with("TODAY · 1,180 / 2,000 kcal\n"));
        assert!(t.contains("eaten: 1180 kcal"));
        assert!(t.contains("• lunch · rice + chicken — ≈ 650 kcal"));
        assert!(t.contains("! low on: eggs, milk"));
    }

    /// The #670 golden fixture every renderer's test reads
    /// (`e2e/fixtures/cards/`): the protocol pins the parse + the plain-text
    /// (v0 `doc`) rendering; the console's CardView snapshot pins the HTML.
    #[test]
    fn golden_chef_day_parses_and_renders_plain_text() {
        const CHEF_DAY: &str = include_str!("../../../e2e/fixtures/cards/chef-day.json");
        let card = parse_card(CHEF_DAY.as_bytes()).expect("golden card parses");
        assert_eq!(card.card, CARD_SCHEMA);
        assert_eq!(card.title, "Chef · today");
        assert_eq!(card.metrics.len(), 2);
        assert_eq!(card.sections.len(), 3);
        assert_eq!(card.alerts.len(), 1);
        let ids: Vec<&str> = card.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            ["dinner.cooked", "dinner.swap", "fridge.request-photo"]
        );
        assert_eq!(card.actions[1].args["reason"], "tap");
        let text = card.to_plain_text();
        assert!(text
            .starts_with("Chef · today\nTue 9 Sep · the family ate 3 meals\nProtein: 62 g / 90\n"));
        assert!(text.contains("[Fridge]\n• Milk — last seen 2 days ago\n"));
        assert!(text.ends_with("! Milk is running low — add to the shopping list?\n"));
        // A round-trip keeps every field (additive evolution: unknown keys are
        // the only thing a re-serialize may drop — the fixture has none).
        let back: CardDocument =
            serde_json::from_str(&serde_json::to_string(&card).unwrap()).unwrap();
        assert_eq!(back, card);
    }
}
