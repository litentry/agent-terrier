//! The daemon-ADVERTISED actions of a sandbox delegate (2026-09-24 — plan
//! `docs/plan/dsh-plugin-abstraction.md` PR 1; spec `delegate-runtime-dsh.md`
//! §4.2 "Advertised actions").
//!
//! The in-pod `agentkeys-daemon` owns the delegate's verbs — `publish_to_slot`
//! (one event to a bound pub slot) and `propose_to_owner` (one learning into
//! the owner's review queue) — and advertises them at
//! `GET /v1/sandbox/self/actions`. The dsh suite's generic `actions` plugin
//! registers one model-facing tool per entry and runs each call as ONE
//! bearer-gated `POST <route>`: no child process, no shell helper, and no
//! second copy of the slot list, the namespace default or the receipt shape
//! in TypeScript. The guard allows a verb when the delegate holds ANY grant
//! of the family the entry declares (`requires_grant_prefix`); WHICH feed or
//! namespace is the cap-mint's verdict at the daemon.
//!
//! ONE owner (D7): these types ARE the wire. The suite's parser is pinned to
//! the same `e2e/fixtures/bridge-protocol/actions_contract.json` this module's
//! test reads, so a renamed field or a changed description fails on whichever
//! side drifted.

use serde::{Deserialize, Serialize};

use crate::ChannelEventKind;

/// `GET` — the advertised list ([`SandboxActionsResponse`]).
pub const SANDBOX_ACTIONS_ROUTE: &str = "/v1/sandbox/self/actions";
/// `POST` — [`SandboxPublishRequest`] → a publish receipt.
pub const SANDBOX_PUBLISH_ROUTE: &str = "/v1/sandbox/self/publish";
/// `POST` — [`SandboxProposeRequest`] → a proposal receipt.
pub const SANDBOX_PROPOSE_ROUTE: &str = "/v1/sandbox/self/propose";

pub const PUBLISH_ACTION: &str = "publish_to_slot";
pub const PROPOSE_ACTION: &str = "propose_to_owner";
/// The grant families the two verbs project (spec §4.2): publishing IS the
/// `channel-pub:<id>` data service, proposing IS the `proposal:<ns>` one.
pub const PUBLISH_GRANT_PREFIX: &str = "channel-pub:";
pub const PROPOSE_GRANT_PREFIX: &str = "proposal:";
/// The reserved slot name of the owner chat — always a valid publish target.
pub const OPCHAT_SLOT_NAME: &str = "opchat";
/// The context kinds a proposal may carry (`persona` is never adoptable).
pub const PROPOSAL_KINDS: [&str; 2] = ["knowledge", "skill"];

/// Every receipt carries these two besides its own fields: `outcome` (the
/// verb's past tense) and `summary` (the one line the tool renders).
pub const RECEIPT_COMMON_FIELDS: [&str; 2] = ["outcome", "summary"];

/// One model-facing parameter of an advertised action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxActionParam {
    pub name: String,
    /// The JSON-schema primitive: `string` for every parameter today.
    pub kind: String,
    pub required: bool,
    pub description: String,
    /// A closed value set (`enum` in the tool schema); empty = free text.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
}

/// One advertised action: what the suite registers as a tool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxAction {
    pub name: String,
    pub description: String,
    /// The daemon route the call POSTs to (path only; the suite prefixes the
    /// daemon base URL).
    pub route: String,
    /// The grant family the guard checks for presence (`channel-pub:` …).
    pub requires_grant_prefix: String,
    pub parameters: Vec<SandboxActionParam>,
    /// The receipt keys every 2xx reply carries besides
    /// [`RECEIPT_COMMON_FIELDS`].
    pub receipt_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxActionsResponse {
    pub actions: Vec<SandboxAction>,
}

/// `POST /v1/sandbox/self/publish` body — the `publish_to_slot` arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPublishRequest {
    /// A bound slot name (or `opchat`), else a raw channel id.
    pub slot: String,
    /// The event kind; absent = `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The body verbatim (the card JSON for `doc`, the line for `text`).
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// `POST /v1/sandbox/self/propose` body — the `propose_to_owner` arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxProposeRequest {
    pub text: String,
    /// Absent = the delegate's own namespace (the daemon's default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// `knowledge` (default) | `skill`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

/// The event kinds a delegate publishes: the wire's `ChannelEventKind` minus
/// `lifecycle` (only the runtime emits that), in wire spelling.
pub fn publishable_event_kinds() -> Vec<String> {
    ChannelEventKind::ALL
        .iter()
        .filter(|k| !matches!(k, ChannelEventKind::Lifecycle))
        .map(|k| k.as_str().to_string())
        .collect()
}

/// The two advertised actions for a delegate that may publish to `pub_slots`
/// (the bound pub/duplex slot NAMES, `opchat` included) and proposes into
/// `own_namespace` by default (`None` = the daemon could derive none).
/// Pure — the daemon's `GET /v1/sandbox/self/actions` is this over its env.
pub fn advertised_actions(pub_slots: &[String], own_namespace: Option<&str>) -> Vec<SandboxAction> {
    let slot_list = pub_slots.join(", ");
    let own_note = match own_namespace.map(str::trim).filter(|s| !s.is_empty()) {
        Some(ns) => format!(
            " Your own namespace is {ns}; that is the default — leave the namespace out unless \
             the owner told you which shared one you may propose into."
        ),
        None => String::new(),
    };
    vec![
        SandboxAction {
            name: PUBLISH_ACTION.to_string(),
            description: format!(
                "Publish ONE event to a feed this application is bound to — the only way anything \
                 reaches a screen, a chat, or a device (a file you write publishes nothing). \
                 kind `doc` with the card JSON as `body` puts a card on a display slot; `text` \
                 sends a line to a chat slot; `command` drives an actuator; the `opchat` slot is \
                 your owner’s chat. Slots you can publish to now: {slot_list}. A refused slot was \
                 not granted at install — say so in your reply instead of retrying."
            ),
            route: SANDBOX_PUBLISH_ROUTE.to_string(),
            requires_grant_prefix: PUBLISH_GRANT_PREFIX.to_string(),
            parameters: vec![
                SandboxActionParam {
                    name: "slot".into(),
                    kind: "string".into(),
                    required: true,
                    description: format!("The bound slot name (one of: {slot_list}) or a channel id."),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "kind".into(),
                    kind: "string".into(),
                    required: false,
                    description: "The event kind; default text. A card is doc.".into(),
                    choices: publishable_event_kinds(),
                },
                SandboxActionParam {
                    name: "body".into(),
                    kind: "string".into(),
                    required: true,
                    description: "The event body, verbatim: the card JSON (card: 1 contract) for doc, the message for text, the command JSON for command.".into(),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "correlation".into(),
                    kind: "string".into(),
                    required: false,
                    description: "Optional: the id of the event this answers (a command you act on), so the reply threads to it.".into(),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "content_type".into(),
                    kind: "string".into(),
                    required: false,
                    description: "Optional media type; the default follows the kind (doc = the card type).".into(),
                    choices: vec![],
                },
            ],
            receipt_fields: ["slot", "channel_id", "kind", "bytes", "correlation"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
        SandboxAction {
            name: PROPOSE_ACTION.to_string(),
            description: format!(
                "Propose ONE durable learning to your owner — a standing preference, a fact about \
                 the household, a rule you were told — so it can outlive this sandbox and reach the \
                 other applications. It lands in the owner’s review queue; nothing enters shared \
                 knowledge until they accept it. Propose the distilled learning (a few sentences), \
                 never a transcript; batch related learnings into one proposal. A namespace you are \
                 not granted to propose into is refused — say so in your reply instead of \
                 retrying.{own_note}"
            ),
            route: SANDBOX_PROPOSE_ROUTE.to_string(),
            requires_grant_prefix: PROPOSE_GRANT_PREFIX.to_string(),
            parameters: vec![
                SandboxActionParam {
                    name: "text".into(),
                    kind: "string".into(),
                    required: true,
                    description: "The learning, distilled: what to keep and why it matters.".into(),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "namespace".into(),
                    kind: "string".into(),
                    required: false,
                    description: "The knowledge namespace it belongs to (default: your own).".into(),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "key".into(),
                    kind: "string".into(),
                    required: false,
                    description: "Optional stable key, so a refined proposal replaces the earlier one.".into(),
                    choices: vec![],
                },
                SandboxActionParam {
                    name: "kind".into(),
                    kind: "string".into(),
                    required: false,
                    description: "knowledge (default) or skill.".into(),
                    choices: PROPOSAL_KINDS.iter().map(|s| s.to_string()).collect(),
                },
            ],
            receipt_fields: ["namespace", "key", "kind", "content_hash"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str =
        include_str!("../../../e2e/fixtures/bridge-protocol/actions_contract.json");

    #[derive(Deserialize)]
    struct Fixture {
        advertised: Advertised,
        publish_request: SandboxPublishRequest,
        propose_request: SandboxProposeRequest,
        publish_receipt: serde_json::Value,
        propose_receipt: serde_json::Value,
    }

    #[derive(Deserialize)]
    struct Advertised {
        pub_slots: Vec<String>,
        own_namespace: String,
        response: SandboxActionsResponse,
    }

    #[test]
    fn the_advertised_actions_match_the_shared_fixture() {
        // The TypeScript side (packages/agentkeys-dsh/tests/actions.spec.ts)
        // registers tools from the SAME document, so the descriptions, the
        // parameters and the grant families cannot drift between the daemon
        // and the suite without one of the two tests going red.
        let f: Fixture = serde_json::from_str(FIXTURE).expect("fixture parses");
        let built = advertised_actions(&f.advertised.pub_slots, Some(&f.advertised.own_namespace));
        assert_eq!(
            built, f.advertised.response.actions,
            "advertised_actions() drifted from e2e/fixtures/bridge-protocol/actions_contract.json"
        );
        let names: Vec<&str> = built.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec![PUBLISH_ACTION, PROPOSE_ACTION]);
        assert!(built[0].requires_grant_prefix.ends_with(':'));
        assert!(built[1].requires_grant_prefix.ends_with(':'));
    }

    #[test]
    fn the_request_bodies_round_trip_and_receipts_carry_the_common_fields() {
        let f: Fixture = serde_json::from_str(FIXTURE).expect("fixture parses");
        let again: SandboxPublishRequest =
            serde_json::from_str(&serde_json::to_string(&f.publish_request).unwrap()).unwrap();
        assert_eq!(again, f.publish_request);
        let again: SandboxProposeRequest =
            serde_json::from_str(&serde_json::to_string(&f.propose_request).unwrap()).unwrap();
        assert_eq!(again, f.propose_request);
        for receipt in [&f.publish_receipt, &f.propose_receipt] {
            for key in RECEIPT_COMMON_FIELDS {
                assert!(
                    receipt.get(key).and_then(|v| v.as_str()).is_some(),
                    "receipt lacks {key}"
                );
            }
        }
        for key in &f.advertised.response.actions[0].receipt_fields {
            assert!(
                f.publish_receipt.get(key).is_some(),
                "publish receipt lacks {key}"
            );
        }
        for key in &f.advertised.response.actions[1].receipt_fields {
            assert!(
                f.propose_receipt.get(key).is_some(),
                "propose receipt lacks {key}"
            );
        }
    }

    #[test]
    fn publishable_kinds_are_every_wire_kind_but_lifecycle() {
        let kinds = publishable_event_kinds();
        assert!(kinds.contains(&"doc".to_string()));
        assert!(!kinds.contains(&"lifecycle".to_string()));
        for k in &kinds {
            assert!(ChannelEventKind::parse(k).is_some(), "{k} must parse back");
        }
    }

    #[test]
    fn no_namespace_means_no_default_note() {
        let built = advertised_actions(&["opchat".to_string()], None);
        assert!(!built[1].description.contains("Your own namespace"));
        assert!(built[0]
            .description
            .contains("Slots you can publish to now: opchat."));
    }
}
