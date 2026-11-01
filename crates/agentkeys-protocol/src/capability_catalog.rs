//! The capability classes' metadata — ONE place (owner ask 2026-09-24: with
//! many applications, what the owner reads about a capability is data, never
//! names and words hard-coded in a UI).
//!
//! A class (`tool:<class>`) is platform vocabulary: the same for every
//! application. This catalog holds everything a surface says about one — its
//! icon, title and explanation (English + 中文) — and the one fact the install
//! sheet acts on: `acts_on_its_own`, a class that lets an application act with
//! no one asking, which the sheet highlights with the class's badge and note.
//! What an APPLICATION does with a class (chef's 07:00 plan) is the template's
//! data (`schedule[]`), never this catalog's.
//!
//! Consumers, all reading this table: the #614 class list below (the validator,
//! the daemon's hash→name recovery), and the console — through the generated
//! `apps/parent-control/lib/generated/capabilityCatalog.ts`, which the test
//! `export_console_catalog` writes (`cargo test -p agentkeys-protocol`) and
//! CI's `git diff --exit-code` over the generated folder keeps current.

use serde::{Deserialize, Serialize};

/// One class's metadata, as the table below holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityClassDef {
    /// The bare class; the grant is `tool:<class>`.
    pub class: &'static str,
    pub icon: &'static str,
    pub title: &'static str,
    pub title_zh: &'static str,
    /// What the grant lets an application do, in the owner's words.
    pub why: &'static str,
    pub why_zh: &'static str,
    /// The class lets an application act with no one asking (a clock). The
    /// install sheet highlights it with `badge` and opens onto the
    /// template's scheduled tasks and `note`. Exactly one class carries it —
    /// [`SCHEDULE_CLASS`], the one a template's `schedule[]` runs under
    /// (pinned by a test below).
    pub acts_on_its_own: bool,
    pub badge: &'static str,
    pub badge_zh: &'static str,
    pub note: &'static str,
    pub note_zh: &'static str,
}

/// The class a template's `schedule[]` entries run under: the validator
/// refuses schedule entries without it (`schedule_requires_tool`), and it is
/// the catalog's one class that acts on its own.
pub const SCHEDULE_CLASS: &str = "schedule";

/// The catalog. Adding a class = one row here (plus the runtime guard's tool
/// mapping, `packages/agentkeys-dsh/src/mapping.ts`, which decides which tool
/// names the class governs).
pub const CAPABILITY_CLASSES: [CapabilityClassDef; 3] = [
    CapabilityClassDef {
        class: "web",
        icon: "\u{2601}",
        title: "Web access",
        title_zh: "联网访问",
        why: "let it fetch pages and search the web while working on your task",
        why_zh: "允许它在处理你的任务时浏览网页、搜索网络",
        acts_on_its_own: false,
        badge: "",
        badge_zh: "",
        note: "",
        note_zh: "",
    },
    CapabilityClassDef {
        class: "code",
        icon: "\u{2328}",
        title: "Code execution",
        title_zh: "运行代码",
        why: "let it run code and shell commands inside its own sandbox",
        why_zh: "允许它在自己的沙箱里运行代码和命令",
        acts_on_its_own: false,
        badge: "",
        badge_zh: "",
        note: "",
        note_zh: "",
    },
    CapabilityClassDef {
        class: SCHEDULE_CLASS,
        icon: "\u{23f1}",
        title: "Scheduled reports",
        title_zh: "定时任务",
        why: "let it run on a schedule (a daily report) without you asking each time",
        why_zh: "允许它按时间表自动运行（例如每日报告），无需你每次发起",
        acts_on_its_own: true,
        badge: "runs on its own",
        badge_zh: "定时运行",
        note: "Each task runs by itself at that time, with no one asking, and its reply appears in the app’s chat. \
               This capability also lets the app set its own reminders while it talks with you; those end when that conversation ends.",
        note_zh: "每项任务到点自动运行，无需任何人发起，回复会出现在应用的对话中。\
                  此能力也允许应用在与你对话时设置自己的提醒，对话结束时提醒随之结束。",
    },
];

/// The #614 capability-service vocabulary — the tool classes the guard maps
/// (`tool:<class>`), DERIVED from the catalog (one owner): the validator and
/// the daemon's hash→name recovery read this list.
pub const TOOL_CLASSES: [&str; 3] = [
    CAPABILITY_CLASSES[0].class,
    CAPABILITY_CLASSES[1].class,
    CAPABILITY_CLASSES[2].class,
];

/// One class's metadata on the wire (the console's generated catalog).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[ts(export, export_to = "../../../apps/parent-control/lib/generated/")]
pub struct CapabilityClassInfo {
    pub class: String,
    /// The grant string, `tool:<class>`.
    pub service: String,
    pub icon: String,
    pub title: String,
    pub title_zh: String,
    pub why: String,
    pub why_zh: String,
    pub acts_on_its_own: bool,
    /// Empty unless `acts_on_its_own`.
    pub badge: String,
    pub badge_zh: String,
    pub note: String,
    pub note_zh: String,
}

impl From<&CapabilityClassDef> for CapabilityClassInfo {
    fn from(d: &CapabilityClassDef) -> Self {
        Self {
            class: d.class.to_string(),
            service: format!("tool:{}", d.class),
            icon: d.icon.to_string(),
            title: d.title.to_string(),
            title_zh: d.title_zh.to_string(),
            why: d.why.to_string(),
            why_zh: d.why_zh.to_string(),
            acts_on_its_own: d.acts_on_its_own,
            badge: d.badge.to_string(),
            badge_zh: d.badge_zh.to_string(),
            note: d.note.to_string(),
            note_zh: d.note_zh.to_string(),
        }
    }
}

/// The whole catalog, in table order.
pub fn capability_catalog() -> Vec<CapabilityClassInfo> {
    CAPABILITY_CLASSES
        .iter()
        .map(CapabilityClassInfo::from)
        .collect()
}

/// One class by its grant (`tool:schedule`) or bare name (`schedule`).
pub fn capability_class(service_or_class: &str) -> Option<CapabilityClassInfo> {
    let class = crate::normalize_tool_class(service_or_class);
    CAPABILITY_CLASSES
        .iter()
        .find(|d| d.class == class)
        .map(CapabilityClassInfo::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATED: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/parent-control/lib/generated/capabilityCatalog.ts"
    );

    fn console_module() -> String {
        let json = serde_json::to_string_pretty(&capability_catalog()).expect("catalog serializes");
        format!(
            "// GENERATED by agentkeys-protocol (`capability_catalog::tests::export_console_catalog`) — do not edit.\n\
             // The capability classes' metadata has ONE owner: `CAPABILITY_CLASSES` in\n\
             // crates/agentkeys-protocol/src/capability_catalog.rs. `cargo test -p agentkeys-protocol`\n\
             // regenerates this file; CI fails on an uncommitted difference.\n\
             import type {{ CapabilityClassInfo }} from \"./CapabilityClassInfo\";\n\
             \n\
             export const CAPABILITY_CATALOG: CapabilityClassInfo[] = {json};\n"
        )
    }

    #[test]
    fn export_console_catalog() {
        // The ts-rs pattern for data: `cargo test` writes the console's copy,
        // CI's `git diff --exit-code apps/parent-control/lib/generated/` fails
        // on a table change nobody regenerated.
        let body = console_module();
        if std::fs::read_to_string(GENERATED).ok().as_deref() != Some(body.as_str()) {
            std::fs::write(GENERATED, &body).expect("write the console's capability catalog");
        }
    }

    #[test]
    fn the_class_list_is_the_catalog() {
        let classes: Vec<&str> = CAPABILITY_CLASSES.iter().map(|d| d.class).collect();
        assert_eq!(classes, TOOL_CLASSES.to_vec());
        let catalog = capability_catalog();
        assert_eq!(catalog.len(), TOOL_CLASSES.len());
        for c in &catalog {
            assert_eq!(c.service, format!("tool:{}", c.class));
        }
    }

    #[test]
    fn every_class_speaks_both_languages_and_only_autonomous_ones_carry_a_badge() {
        for d in CAPABILITY_CLASSES {
            for (field, text) in [
                ("icon", d.icon),
                ("title", d.title),
                ("title_zh", d.title_zh),
                ("why", d.why),
                ("why_zh", d.why_zh),
            ] {
                assert!(!text.trim().is_empty(), "{}: {field} is empty", d.class);
            }
            let badge_fields = [d.badge, d.badge_zh, d.note, d.note_zh];
            if d.acts_on_its_own {
                assert!(
                    badge_fields.iter().all(|t| !t.trim().is_empty()),
                    "{}: an autonomous class needs its badge and note in both languages",
                    d.class
                );
            } else {
                assert!(
                    badge_fields.iter().all(|t| t.is_empty()),
                    "{}: only an autonomous class carries a badge",
                    d.class
                );
            }
        }
    }

    #[test]
    fn the_one_class_that_acts_on_its_own_is_the_one_schedule_entries_run_under() {
        // The sheet opens a class that acts on its own onto the template's
        // `schedule[]` — today the only work an app does with no one asking.
        // A second such class needs its own task source on the sheet (compile
        // it into the grant's `ServiceAnnotation`) before this is relaxed.
        let autonomous: Vec<&str> = CAPABILITY_CLASSES
            .iter()
            .filter(|d| d.acts_on_its_own)
            .map(|d| d.class)
            .collect();
        assert_eq!(autonomous, vec![SCHEDULE_CLASS]);
    }

    #[test]
    fn a_class_is_found_by_its_grant_or_its_name() {
        assert_eq!(
            capability_class("tool:schedule").map(|c| c.acts_on_its_own),
            Some(true)
        );
        assert_eq!(
            capability_class(" Schedule ").map(|c| c.class),
            Some("schedule".to_string())
        );
        assert_eq!(
            capability_class("tool:web").map(|c| c.acts_on_its_own),
            Some(false)
        );
        assert!(capability_class("tool:teleport").is_none());
    }
}
