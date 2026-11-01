//! #668 — the R2 PERCEPTION ADAPTER (plan §4.4 R2): a media event (`image`,
//! `frame`, `audio-clip`) becomes a model turn the agent's skills can act on.
//!
//! One adapter behind the two per-kind paths the daemon already had
//! (`vision_turn` #528, `voice_turn` #519): a PRE-TURN runs the app's own
//! perception prompt (template content — `skills/perception.md`, rule F1:
//! the framework never names a domain) on the FULL-RESOLUTION original
//! (inline body or the `body_ref` blob fetched from the feed — never
//! downscaled; the model provider handles resolution), yields a structured
//! result, and the result is handed to `/v1/chat` as the agent's turn. A
//! low-confidence result asks the contact for a closer photo instead of
//! guessing. Perception is keyed by content hash (the same photo decoded
//! once — plan O3).
//!
//! Everything that shapes bytes is PURE + unit-tested here; the two network
//! legs (the gate vision / ASR call, the blob fetch) are thin.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The default confidence floor below which the adapter asks for a closer
/// photo instead of running the agent turn. Override:
/// `AGENTKEYS_PERCEPTION_MIN_CONFIDENCE` (0..=1).
pub const DEFAULT_MIN_CONFIDENCE: f32 = 0.4;

/// The framework's kind-neutral fallback prompt when the template ships no
/// `skills/perception.md`: describe, list facts, rate confidence.
pub const DEFAULT_PERCEPTION_PROMPT: &str = "You are the perception step in front of an \
assistant. Describe what this input shows and list the concrete facts an assistant could act on.";

/// The JSON contract the pre-turn asks the model for (appended to every
/// perception prompt so the app's prompt never has to restate it).
pub const RESULT_CONTRACT: &str = "Answer with ONE JSON object and nothing else: \
{\"summary\": \"<one or two sentences>\", \"facts\": [\"<fact>\", ...], \
\"confidence\": <0.0-1.0 how sure you are the input is clear enough to act on>, \
\"needs_closer_look\": <true when a closer or clearer photo would change the facts>}";

/// The structured pre-turn result — DATA for the agent, never a tool call
/// (small-model ledger seam S6: confidence is mandatory so the app can ask for
/// a better photo).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerceptionResult {
    pub summary: String,
    #[serde(default)]
    pub facts: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub needs_closer_look: bool,
    /// `sha256` of the ORIGINAL bytes — the cache key + the "bytes unchanged"
    /// proof the agent turn cites.
    #[serde(default)]
    pub content_sha256: String,
}

fn default_confidence() -> f32 {
    0.5
}

/// Compose the gate `/v1/chat/completions` body for an IMAGE pre-turn: the
/// original as a data URI (its real content type, never re-encoded) + the
/// app's prompt + the JSON contract. ARK/Doubao accept the standard
/// `image_url` content part (#528).
pub fn image_request_body(prompt: &str, content_type: &str, image_b64: &str) -> serde_json::Value {
    let ct = if content_type.trim().is_empty() {
        "image/jpeg"
    } else {
        content_type.trim()
    };
    serde_json::json!({
        "messages": [{
            "role": "user",
            "content": [
                { "type": "image_url",
                  "image_url": { "url": format!("data:{ct};base64,{image_b64}") } },
                { "type": "text", "text": format!("{}\n\n{}", prompt.trim(), RESULT_CONTRACT) }
            ]
        }],
        "stream": false
    })
}

/// Compose the text-only pre-turn body for an AUDIO clip: the ASR transcript
/// (the gate's `/v1/audio/transcriptions`, #519) under the same prompt +
/// contract.
pub fn transcript_request_body(prompt: &str, transcript: &str) -> serde_json::Value {
    serde_json::json!({
        "messages": [{
            "role": "user",
            "content": format!(
                "{}\n\nThe input is a voice clip; its transcript follows.\n---\n{}\n---\n\n{}",
                prompt.trim(), transcript.trim(), RESULT_CONTRACT
            )
        }],
        "stream": false
    })
}

/// Parse the model's reply into a [`PerceptionResult`]: the first JSON object
/// in the text; a reply with no parseable object degrades to `summary = the
/// text` at the default confidence (never a lost turn).
pub fn parse_result(reply: &str, content_sha256: &str) -> PerceptionResult {
    let trimmed = reply.trim();
    let candidate = match (trimmed.find('{'), trimmed.rfind('}')) {
        (Some(a), Some(b)) if b > a => Some(&trimmed[a..=b]),
        _ => None,
    };
    let mut result = candidate
        .and_then(|c| serde_json::from_str::<PerceptionResult>(c).ok())
        .unwrap_or_else(|| PerceptionResult {
            summary: trimmed.to_string(),
            facts: Vec::new(),
            confidence: default_confidence(),
            needs_closer_look: false,
            content_sha256: String::new(),
        });
    result.confidence = result.confidence.clamp(0.0, 1.0);
    result.content_sha256 = content_sha256.to_string();
    if result.summary.trim().is_empty() {
        result.summary = trimmed.to_string();
    }
    result
}

/// Whether the adapter should ask for a closer look instead of running the
/// agent turn.
pub fn needs_closer_look(result: &PerceptionResult, min_confidence: f32) -> bool {
    result.needs_closer_look || result.confidence < min_confidence
}

/// The reply the adapter sends back on the SOURCE feed when the input was not
/// clear enough (bilingual — the contact's language is unknown at this layer).
pub fn closer_look_reply(kind: &str) -> String {
    match kind {
        "audio-clip" => "I couldn't make that out clearly — could you say it again, a little \
                         slower? · 没听清，请再说一遍，慢一点。"
            .to_string(),
        _ => "I can't see this clearly enough to be sure — could you send a closer, brighter \
              photo? · 看不太清，请拍一张更近、更亮的照片。"
            .to_string(),
    }
}

/// The agent turn the pre-turn hands to `/v1/chat`: provenance-tagged (slot,
/// kind, contact tier, confidence) so the app's skills know WHAT arrived and
/// FROM WHOM, the structured facts, and the contact's caption when one rode
/// with the media. The framework names kinds, never domains.
pub fn agent_turn_text(
    slot: &str,
    kind: &str,
    contact_tier: Option<&str>,
    caption: Option<&str>,
    result: &PerceptionResult,
) -> String {
    let mut out = format!(
        "[perceived {kind} · slot {slot}{} · confidence {:.2} · sha256 {}]\n{}",
        contact_tier
            .map(|t| format!(" · from a {t} contact"))
            .unwrap_or_default(),
        result.confidence,
        &result.content_sha256[..result.content_sha256.len().min(12)],
        result.summary.trim()
    );
    if !result.facts.is_empty() {
        out.push_str("\nfacts:");
        for f in &result.facts {
            out.push_str(&format!("\n- {}", f.trim()));
        }
    }
    if let Some(c) = caption.map(str::trim).filter(|c| !c.is_empty()) {
        out.push_str(&format!("\ncaption from the sender: {c}"));
    }
    out
}

/// A bounded content-hash → result cache (plan O3 — the same photo decoded
/// once). Insertion order eviction at `cap`.
#[derive(Debug, Default)]
pub struct PerceptionCache {
    map: HashMap<String, PerceptionResult>,
    order: Vec<String>,
    cap: usize,
}

impl PerceptionCache {
    pub fn new(cap: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: Vec::new(),
            cap: cap.max(1),
        }
    }

    pub fn get(&self, sha256: &str) -> Option<&PerceptionResult> {
        self.map.get(sha256)
    }

    pub fn put(&mut self, sha256: String, result: PerceptionResult) {
        if !self.map.contains_key(&sha256) {
            self.order.push(sha256.clone());
            if self.order.len() > self.cap {
                let old = self.order.remove(0);
                self.map.remove(&old);
            }
        }
        self.map.insert(sha256, result);
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Read the confidence floor from a lookup (env at the call site).
pub fn min_confidence_from(lookup: impl Fn(&str) -> Option<String>) -> f32 {
    lookup("AGENTKEYS_PERCEPTION_MIN_CONFIDENCE")
        .and_then(|v| v.trim().parse::<f32>().ok())
        .filter(|c| (0.0..=1.0).contains(c))
        .unwrap_or(DEFAULT_MIN_CONFIDENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_body_keeps_the_real_content_type_and_appends_the_contract() {
        let body = image_request_body("Look at the fridge.", "image/png", "AAAA");
        let content = &body["messages"][0]["content"];
        assert_eq!(content[0]["image_url"]["url"], "data:image/png;base64,AAAA");
        let text = content[1]["text"].as_str().unwrap();
        assert!(text.starts_with("Look at the fridge."));
        assert!(text.contains("\"confidence\""));
        // Empty content type defaults to jpeg (the pre-#667 inline posture).
        let body = image_request_body("p", "", "BB");
        assert_eq!(
            body["messages"][0]["content"][0]["image_url"]["url"],
            "data:image/jpeg;base64,BB"
        );
    }

    #[test]
    fn transcript_body_carries_the_transcript_under_the_prompt() {
        let body = transcript_request_body("Note the request.", "buy milk");
        let text = body["messages"][0]["content"].as_str().unwrap();
        assert!(text.contains("buy milk"));
        assert!(text.contains("\"summary\""));
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn parse_result_reads_json_and_degrades_to_text() {
        let r = parse_result(
            "Sure! {\"summary\": \"rice and chicken\", \"facts\": [\"rice\", \"chicken\"], \
             \"confidence\": 0.87, \"needs_closer_look\": false} thanks",
            "abc",
        );
        assert_eq!(r.summary, "rice and chicken");
        assert_eq!(r.facts, vec!["rice", "chicken"]);
        assert!((r.confidence - 0.87).abs() < 1e-6);
        assert_eq!(r.content_sha256, "abc");
        let plain = parse_result("just a description", "def");
        assert_eq!(plain.summary, "just a description");
        assert_eq!(plain.confidence, DEFAULT_MIN_CONFIDENCE + 0.1);
        // Out-of-range confidence is clamped; an empty summary falls back.
        let clamped = parse_result("{\"summary\": \"\", \"confidence\": 7}", "x");
        assert_eq!(clamped.confidence, 1.0);
        assert!(!clamped.summary.is_empty());
    }

    #[test]
    fn low_confidence_asks_for_a_closer_look() {
        let low = parse_result("{\"summary\": \"blurry\", \"confidence\": 0.2}", "h");
        assert!(needs_closer_look(&low, DEFAULT_MIN_CONFIDENCE));
        let flagged = parse_result(
            "{\"summary\": \"ok\", \"confidence\": 0.9, \"needs_closer_look\": true}",
            "h",
        );
        assert!(needs_closer_look(&flagged, DEFAULT_MIN_CONFIDENCE));
        let fine = parse_result("{\"summary\": \"ok\", \"confidence\": 0.9}", "h");
        assert!(!needs_closer_look(&fine, DEFAULT_MIN_CONFIDENCE));
        assert!(closer_look_reply("image").contains("closer"));
        assert!(closer_look_reply("audio-clip").contains("again"));
    }

    #[test]
    fn agent_turn_is_provenance_tagged_and_domain_free() {
        let r = PerceptionResult {
            summary: "two items on a shelf".into(),
            facts: vec!["item A".into(), "item B".into()],
            confidence: 0.91,
            needs_closer_look: false,
            content_sha256: "0123456789abcdef".into(),
        };
        let t = agent_turn_text("family_chat", "image", Some("owner"), Some("dinner?"), &r);
        assert!(t.starts_with("[perceived image · slot family_chat · from a owner contact · confidence 0.91 · sha256 0123456789ab]"));
        assert!(t.contains("- item A"));
        assert!(t.ends_with("caption from the sender: dinner?"));
        let bare = agent_turn_text("cam", "frame", None, None, &r);
        assert!(!bare.contains("from a"));
        assert!(!bare.contains("caption"));
    }

    #[test]
    fn cache_is_keyed_by_hash_and_bounded() {
        let mut c = PerceptionCache::new(2);
        let r = |s: &str| PerceptionResult {
            summary: s.into(),
            facts: vec![],
            confidence: 1.0,
            needs_closer_look: false,
            content_sha256: String::new(),
        };
        c.put("a".into(), r("a"));
        c.put("b".into(), r("b"));
        c.put("c".into(), r("c"));
        assert!(c.get("a").is_none());
        assert_eq!(c.get("c").unwrap().summary, "c");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(min_confidence_from(|_| Some("0.7".into())), 0.7);
        assert_eq!(
            min_confidence_from(|_| Some("7".into())),
            DEFAULT_MIN_CONFIDENCE
        );
    }
}
