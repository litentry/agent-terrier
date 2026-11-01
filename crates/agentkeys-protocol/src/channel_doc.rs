//! The household channel document. A channel is the unit of context: what
//! it is for, who is in it, and which apps are bound to it and why. The contact
//! gate's router reads nothing else; the console edits it; every write is live
//! — no redeploy, no Touch ID — because a document grants nothing: the on-chain
//! `channel-pub/sub:<id>` pairs stay the authority (D1), and a member's row is
//! a policy the gate enforces exactly as `reach` was.

use serde::{Deserialize, Serialize};

use crate::{ChannelEventKind, ContactTier};

/// The slot name an app's operator channel (`opchat-<label>`) is bound under.
pub const OPCHAT_SLOT_NAME: &str = "opchat";
/// The app's row description on its operator channel — what it does there.
pub const OPCHAT_DESCRIPTION_ZH: &str = "接收操作者对它的指令、设置与批准";

/// An operator channel's display name and purpose, from the app's label.
pub fn opchat_display_name(label: &str) -> String {
    format!("{label}·操作")
}

pub fn opchat_purpose(label: &str) -> String {
    format!(
        "对 {label} 本身的指令，不是日常请求：它该怎么工作、它的设置、批准或拒绝它提出的建议 \
         例如：「把早上的计划改成七点半发」、「回答简短点」、「批准你提的那个清单」、「先停一下你的提醒」"
    )
}

/// The binding description an install seeds for a messaging slot when the
/// owner wrote none: the slot's reason in the household's language, plus the
/// template's route examples (measured 2026-09-24: examples lift the router's
/// held-out coverage by 16 points). The owner edits it under "edit bindings".
pub fn seed_binding_description(
    reason_zh: &str,
    reason: &str,
    description_zh: &str,
    description: &str,
    route_examples: &[String],
) -> String {
    let base = [reason_zh, reason, description_zh, description]
        .into_iter()
        .map(str::trim)
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .trim_end_matches('。')
        .to_string();
    let examples: Vec<String> = route_examples
        .iter()
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .map(|e| format!("「{e}」"))
        .collect();
    match (base.is_empty(), examples.is_empty()) {
        (_, true) => base,
        (true, false) => format!("例如：{}", examples.join("、")),
        (false, false) => format!("{base} 例如：{}", examples.join("、")),
    }
}

/// One channel as the household sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ChannelDoc {
    /// The immutable anchor — the string the on-chain grants hash.
    pub id: String,
    /// The display name: what a member sees as the `[channel]` label.
    #[serde(default)]
    pub name: String,
    /// What the channel is for, in the owner's words — the first line the
    /// router reads for it.
    #[serde(default)]
    pub purpose: String,
    /// The app this is the operator channel of (`opchat-<label>`): the owner
    /// speaks here; anyone else only by the owner's explicit toggle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub operator_of: Option<String>,
    /// The household default (`#general`): offered first as an app's home at
    /// install, joined by every new member.
    #[serde(default)]
    pub household_default: bool,
    #[serde(default)]
    pub members: Vec<ChannelMember>,
    /// The apps bound to this channel, each with its binding's description.
    #[serde(default)]
    pub apps: Vec<ChannelApp>,
    /// The app that takes an event nobody addressed (the first app bound here
    /// unless the owner picks another).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub default_app: Option<String>,
    /// Unix seconds of the last write — the Route page names the version a
    /// decision was rendered from.
    #[serde(default)]
    #[ts(type = "number")]
    pub updated_at: u64,
}

/// A member's row: may they publish here, do they receive what lands here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ChannelMember {
    pub contact_id: String,
    #[serde(default)]
    pub speak: bool,
    #[serde(default)]
    pub read: bool,
}

/// An app's binding, seen from the channel: the slot it bound the channel
/// under, the binding's description (seeded from the template slot's
/// `reason`, edited under "edit bindings" — the only text the router reads
/// about an app), the event kinds the slot takes, and the tiers its template
/// proposes as members.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ChannelApp {
    pub alias: String,
    #[serde(default)]
    pub slot: String,
    #[serde(default)]
    pub description: String,
    /// Empty = every kind (a row written before the slot declared any).
    #[serde(default)]
    pub takes: Vec<ChannelEventKind>,
    #[serde(default)]
    pub audience: Vec<ContactTier>,
}

/// A membership as a request names it (the contact is the request's own).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ChannelGrant {
    pub channel_id: String,
    #[serde(default)]
    pub speak: bool,
    #[serde(default)]
    pub read: bool,
}

/// A member's row on one channel, as the console shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct ContactChannelView {
    pub channel_id: String,
    pub name: String,
    pub speak: bool,
    pub read: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub operator_of: Option<String>,
}

impl ChannelDoc {
    pub fn new(id: &str, name: &str) -> Self {
        ChannelDoc {
            id: id.trim().to_string(),
            name: name.trim().to_string(),
            ..Default::default()
        }
    }

    pub fn is_operator(&self) -> bool {
        self.operator_of.is_some()
    }

    /// The `[channel]` label: the name, else the id.
    pub fn display_name(&self) -> &str {
        if self.name.trim().is_empty() {
            &self.id
        } else {
            self.name.trim()
        }
    }

    pub fn app(&self, alias: &str) -> Option<&ChannelApp> {
        self.apps
            .iter()
            .find(|a| a.alias.eq_ignore_ascii_case(alias.trim()))
    }

    pub fn member(&self, contact_id: &str) -> Option<&ChannelMember> {
        self.members.iter().find(|m| m.contact_id == contact_id)
    }

    pub fn speaks(&self, contact_id: &str) -> bool {
        self.member(contact_id).is_some_and(|m| m.speak)
    }

    pub fn reads(&self, contact_id: &str) -> bool {
        self.member(contact_id).is_some_and(|m| m.read)
    }

    /// The app an unaddressed event goes to: `default_app` when it is bound
    /// here, else the only app.
    pub fn default_or_only_app(&self) -> Option<&str> {
        if let Some(d) = self.default_app.as_deref() {
            if self.app(d).is_some() {
                return Some(d);
            }
        }
        match self.apps.as_slice() {
            [one] => Some(one.alias.as_str()),
            _ => None,
        }
    }

    /// Whether `alias` takes `kind` here (no declared kinds = every kind).
    pub fn takes(&self, alias: &str, kind: ChannelEventKind) -> bool {
        match self.app(alias) {
            Some(a) if !a.takes.is_empty() => a.takes.contains(&kind),
            Some(_) => true,
            None => false,
        }
    }

    /// The apps here that take `kind`.
    pub fn apps_taking(&self, kind: ChannelEventKind) -> Vec<&ChannelApp> {
        self.apps
            .iter()
            .filter(|a| a.takes.is_empty() || a.takes.contains(&kind))
            .collect()
    }

    /// Insert or replace the app's row (alias stored lowercase); the first app
    /// bound becomes the default. `true` when anything changed.
    pub fn upsert_app(&mut self, app: ChannelApp) -> bool {
        let alias = app.alias.trim().to_lowercase();
        let row = ChannelApp { alias, ..app };
        let changed = match self.apps.iter_mut().find(|a| a.alias == row.alias) {
            Some(existing) if *existing == row => false,
            Some(existing) => {
                *existing = row.clone();
                true
            }
            None => {
                self.apps.push(row.clone());
                true
            }
        };
        if self.default_app.is_none() && self.apps.len() == 1 {
            self.default_app = Some(row.alias);
            return true;
        }
        changed
    }

    /// Drop the app's row; a default that left is cleared (the only app left
    /// becomes the default through `default_or_only_app`).
    pub fn remove_app(&mut self, alias: &str) -> bool {
        let before = self.apps.len();
        self.apps
            .retain(|a| !a.alias.eq_ignore_ascii_case(alias.trim()));
        if self
            .default_app
            .as_deref()
            .is_some_and(|d| d.eq_ignore_ascii_case(alias.trim()))
        {
            self.default_app = None;
        }
        self.apps.len() != before
    }

    /// Set a member's row; `speak == read == false` removes it. `true` when
    /// anything changed.
    pub fn set_member(&mut self, contact_id: &str, speak: bool, read: bool) -> bool {
        if !speak && !read {
            return self.remove_member(contact_id);
        }
        match self.members.iter_mut().find(|m| m.contact_id == contact_id) {
            Some(m) if m.speak == speak && m.read == read => false,
            Some(m) => {
                m.speak = speak;
                m.read = read;
                true
            }
            None => {
                self.members.push(ChannelMember {
                    contact_id: contact_id.to_string(),
                    speak,
                    read,
                });
                true
            }
        }
    }

    pub fn remove_member(&mut self, contact_id: &str) -> bool {
        let before = self.members.len();
        self.members.retain(|m| m.contact_id != contact_id);
        self.members.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc() -> ChannelDoc {
        let mut d = ChannelDoc::new("family-chat", "家庭群");
        d.upsert_app(ChannelApp {
            alias: "Chef".into(),
            slot: "family_chat".into(),
            description: "饭菜和冰箱的照片从这里发来".into(),
            takes: vec![ChannelEventKind::Text, ChannelEventKind::Image],
            audience: vec![ContactTier::Owner],
        });
        d
    }

    #[test]
    fn the_first_app_bound_is_the_default_and_leaving_clears_it() {
        let mut d = doc();
        assert_eq!(d.default_app.as_deref(), Some("chef"));
        d.upsert_app(ChannelApp {
            alias: "storyteller".into(),
            ..Default::default()
        });
        assert_eq!(d.default_or_only_app(), Some("chef"));
        assert!(d.remove_app("chef"));
        assert_eq!(d.default_app, None);
        assert_eq!(d.default_or_only_app(), Some("storyteller"));
    }

    #[test]
    fn takes_follows_the_declared_kinds_and_an_undeclared_row_takes_everything() {
        let mut d = doc();
        assert!(d.takes("chef", ChannelEventKind::Image));
        assert!(!d.takes("chef", ChannelEventKind::AudioClip));
        assert!(!d.takes("nobody", ChannelEventKind::Text));
        d.upsert_app(ChannelApp {
            alias: "legacy".into(),
            ..Default::default()
        });
        assert!(d.takes("legacy", ChannelEventKind::AudioClip));
        assert_eq!(d.apps_taking(ChannelEventKind::AudioClip).len(), 1);
    }

    #[test]
    fn a_binding_description_is_seeded_from_the_slot_reason_and_the_route_examples() {
        let ex = vec![
            "今晚吃什么".to_string(),
            " ".to_string(),
            "冰箱里还有什么菜".to_string(),
        ];
        assert_eq!(
            seed_binding_description("饭菜的照片从这里发来。", "Meal photos", "", "", &ex),
            "饭菜的照片从这里发来 例如：「今晚吃什么」、「冰箱里还有什么菜」"
        );
        assert_eq!(
            seed_binding_description("", "", "跟踪全家的饮食。", "Tracks meals", &[]),
            "跟踪全家的饮食"
        );
        assert_eq!(
            seed_binding_description("", "", "", "", &ex),
            "例如：「今晚吃什么」、「冰箱里还有什么菜」"
        );
        assert_eq!(opchat_display_name("chef"), "chef·操作");
        assert!(opchat_purpose("chef").contains("例如"));
    }

    #[test]
    fn a_member_row_is_set_changed_and_removed_by_the_false_pair() {
        let mut d = doc();
        assert!(d.set_member("c-mama", true, true));
        assert!(!d.set_member("c-mama", true, true));
        assert!(d.set_member("c-mama", false, true));
        assert!(d.reads("c-mama") && !d.speaks("c-mama"));
        assert!(d.set_member("c-mama", false, false));
        assert!(d.member("c-mama").is_none());
    }
}
