//! #722 — the Jev router tier (#689 leg 1): one WeChat chat, and each plain
//! message finds the app it belongs to. The decision model (TypeSafe's Jev,
//! reached ONLY through the model gate's `/v1/systemone` relay — the contact
//! gate holds a `gk_` relay key, never a vendor key) answers ONE typed question:
//! which of the contact's REACHABLE apps should receive this message, or
//! `unclear`. The candidate set is built from `reach` and nothing else, so the
//! model cannot name an app the contact was not granted (D10 by construction;
//! [`verdict_from`] re-checks the answer anyway).
//!
//! Owner rules (2026-09-23, recorded in #689 + the plan):
//! - **Unsure → ask the person.** Below the threshold the member gets a
//!   numbered ask naming the top candidates; their reply delivers the ORIGINAL
//!   message ([`PendingAsk`], memory-only, TTL). Never a below-threshold route.
//! - **The last agent is context, not a rule.** It rides in the state so a
//!   continuation («再来一个») leans to it, while «讲个故事» after chef goes
//!   to storyteller. An optional code-side weight (default 1 = off) exists for
//!   the eval to tune.
//! - **Gate down / no key / malformed → today's deterministic tier**, visibly.
//!
//! Everything that decides is pure (unit-tested); only [`JevClient`] does I/O.

use std::collections::BTreeMap;
use std::time::Duration;

use agentkeys_protocol::{
    AppBlurb, SystemOneQuestion, SystemOneRequest, SystemOneResponse, JEV_PINNED_MODEL,
    SYSTEMONE_ROUTE,
};
use serde_json::{json, Value};

/// The extra option every request carries: "none of the listed apps fits".
pub const UNCLEAR_OPTION: &str = "unclear";
/// The question key the router asks.
pub const DESTINATION_QUESTION: &str = "destination";
/// How many candidates a numbered ask names.
pub const ASK_CANDIDATES: usize = 3;

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
    /// Route only when the model's confidence clears this; below it, ask.
    pub threshold: f64,
    /// The gate call's budget; on timeout the deterministic tier runs.
    pub timeout_ms: u64,
    /// How long a numbered ask waits for its reply (memory only).
    pub ask_ttl_secs: u64,
    /// D-M4's optional lean toward the last agent (1 = off; the eval sets it).
    pub last_agent_weight: f64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            engine: RouterEngine::Auto,
            gate_url: None,
            gate_key: None,
            model: JEV_PINNED_MODEL.to_string(),
            threshold: 0.6,
            timeout_ms: 3000,
            ask_ttl_secs: 600,
            last_agent_weight: 1.0,
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

/// One option the model may pick: a reachable alias and its blurb, if the
/// console registered one at install.
pub type Candidate = (String, Option<AppBlurb>);

/// Build the ONE question. Options = the candidates (the contact's reach, in
/// reach order) + `unclear`; the last agent is context in the state, never an
/// instruction to stick.
pub fn build_request(
    model: &str,
    message: &str,
    sender_tier: &str,
    last_agent: Option<&str>,
    candidates: &[Candidate],
) -> SystemOneRequest {
    let mut state = json!({
        "message": message,
        "sender_tier": sender_tier,
    });
    let mut instructions = String::from(
        "Who should receive `message`, sent by a family member of tier `sender_tier` \
         to the household's assistants? Pick the assistant whose purpose matches what \
         the message asks for.",
    );
    if let Some(last) = last_agent.map(str::trim).filter(|l| !l.is_empty()) {
        state["last_agent"] = Value::String(last.to_string());
        instructions.push_str(
            " Their previous message went to `last_agent`; a continuation of that \
             conversation belongs to it, a message that clearly asks for another \
             assistant does not.",
        );
    }
    let mut criteria: BTreeMap<String, Value> = BTreeMap::new();
    for (alias, blurb) in candidates {
        let key = alias.trim().to_lowercase();
        if key.is_empty() || key == UNCLEAR_OPTION {
            continue;
        }
        criteria.insert(key, blurb.as_ref().map(blurb_value).unwrap_or(Value::Null));
    }
    criteria.insert(
        UNCLEAR_OPTION.to_string(),
        Value::String("none of the listed assistants clearly fits this message".into()),
    );
    let mut questions = BTreeMap::new();
    questions.insert(
        DESTINATION_QUESTION.to_string(),
        SystemOneQuestion::Choice {
            instructions: Value::String(instructions),
            criteria,
        },
    );
    SystemOneRequest {
        model: model.to_string(),
        state,
        questions,
    }
}

fn blurb_value(b: &AppBlurb) -> Value {
    let mut v = serde_json::Map::new();
    for (k, s) in [
        ("name", &b.name),
        ("name_zh", &b.name_zh),
        ("purpose", &b.purpose),
        ("purpose_zh", &b.purpose_zh),
    ] {
        if !s.trim().is_empty() {
            v.insert(k.to_string(), Value::String(s.clone()));
        }
    }
    if !b.examples.is_empty() {
        v.insert("examples".into(), json!(b.examples));
    }
    if v.is_empty() {
        Value::Null
    } else {
        Value::Object(v)
    }
}

/// The model's answer, reduced to what the relay acts on.
#[derive(Debug, Clone, PartialEq)]
pub enum JevVerdict {
    /// Confident pick — an alias in the contact's reach (canonical spelling).
    Route { alias: String, confidence: f64 },
    /// Below the threshold, or `unclear`: ask, naming these reach aliases
    /// (best first) — never a guess.
    Ask {
        candidates: Vec<String>,
        confidence: f64,
    },
    /// The answer is not usable (an option we never sent, a missing question,
    /// a wrong answer type). Treated exactly like a transport failure: the
    /// deterministic tier runs. Reach-bounding lives here.
    Malformed(String),
}

/// TypeSafe's own approximation of `confidence` from a distribution (the one
/// its docs show): 1 when all mass sits on one option, 0 when even.
/// Recomputed here only when a code-side weight changed the distribution.
fn peak_confidence(probabilities: &BTreeMap<String, f64>) -> f64 {
    let n = probabilities.len();
    if n < 2 {
        return 1.0;
    }
    let peak = probabilities.values().cloned().fold(0.0_f64, f64::max);
    ((n as f64 * peak - 1.0) / (n as f64 - 1.0)).clamp(0.0, 1.0)
}

/// Reduce a response to a verdict. `reach` bounds everything: an option key
/// (or the chosen key) outside `reach ∪ {unclear}` is `Malformed`, never a
/// route. `last_agent_weight != 1` multiplies the last agent's probability
/// and renormalizes before the threshold check (the vendor's `confidence` is
/// then recomputed from the adjusted distribution).
pub fn verdict_from(
    resp: &SystemOneResponse,
    reach: &[String],
    threshold: f64,
    last_agent: Option<&str>,
    last_agent_weight: f64,
) -> JevVerdict {
    let Some((choice, probabilities, vendor_confidence)) = resp.choice(DESTINATION_QUESTION) else {
        return JevVerdict::Malformed(format!("no choice answer under `{DESTINATION_QUESTION}`"));
    };
    let canonical = |key: &str| -> Option<String> {
        reach
            .iter()
            .find(|r| r.trim().eq_ignore_ascii_case(key.trim()))
            .cloned()
    };
    let in_set =
        |key: &str| key.trim().eq_ignore_ascii_case(UNCLEAR_OPTION) || canonical(key).is_some();
    if !in_set(choice) {
        return JevVerdict::Malformed(format!("chose `{choice}`, which is not in reach"));
    }
    if let Some(bad) = probabilities.keys().find(|k| !in_set(k)) {
        return JevVerdict::Malformed(format!("option `{bad}` is not in reach"));
    }
    if probabilities.is_empty() {
        return JevVerdict::Malformed("empty probabilities".into());
    }

    let mut adjusted: BTreeMap<String, f64> = probabilities
        .iter()
        .map(|(k, p)| (k.trim().to_lowercase(), p.max(0.0)))
        .collect();
    let mut confidence = vendor_confidence;
    let weighted = last_agent_weight.is_finite()
        && last_agent_weight > 0.0
        && (last_agent_weight - 1.0).abs() > f64::EPSILON;
    if weighted {
        if let Some(last) = last_agent.and_then(canonical) {
            if let Some(p) = adjusted.get_mut(&last.to_lowercase()) {
                *p *= last_agent_weight;
            }
            let sum: f64 = adjusted.values().sum();
            if sum > 0.0 {
                for p in adjusted.values_mut() {
                    *p /= sum;
                }
            }
            confidence = peak_confidence(&adjusted);
        }
    }

    // The pick: the vendor's choice unless the weighting moved the peak.
    let mut pick = choice.trim().to_lowercase();
    if weighted {
        if let Some((k, _)) = adjusted
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        {
            pick = k.clone();
        }
    }

    let mut ranked: Vec<(String, f64)> = adjusted
        .iter()
        .filter(|(k, _)| k.as_str() != UNCLEAR_OPTION)
        .filter_map(|(k, p)| canonical(k).map(|c| (c, *p)))
        .collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let candidates: Vec<String> = ranked
        .into_iter()
        .take(ASK_CANDIDATES)
        .map(|(alias, _)| alias)
        .collect();

    if pick == UNCLEAR_OPTION || confidence < threshold {
        return JevVerdict::Ask {
            candidates,
            confidence,
        };
    }
    match canonical(&pick) {
        Some(alias) => JevVerdict::Route { alias, confidence },
        None => JevVerdict::Malformed(format!("pick `{pick}` left the reach set")),
    }
}

/// A numbered ask waiting for its reply: the member's ORIGINAL message and
/// the aliases the ask named. Memory only, one per contact, expires — message
/// text never reaches disk or audit (D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAsk {
    pub original_text: String,
    pub candidates: Vec<String>,
    pub expires_at_secs: u64,
}

/// Which candidate a reply picks: a number (`1`, `２`), the alias itself, or
/// `/alias` — anything else is a new message, not an answer.
pub fn parse_ask_reply(text: &str, candidates: &[String]) -> Option<String> {
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
        return (1..=candidates.len())
            .contains(&n)
            .then(|| candidates[n - 1].clone());
    }
    let name = t.trim_start_matches('/').trim().to_lowercase();
    candidates
        .iter()
        .find(|c| c.to_lowercase() == name)
        .cloned()
}

/// The ask the member reads. Names THEIR candidates, numbered, and keeps the
/// deterministic `/alias` escape hatch (it always works).
pub fn ask_text(candidates: &[String], en: bool) -> String {
    if candidates.is_empty() {
        return crate::relay::ask_back_text(&[], en);
    }
    let numbered: Vec<String> = candidates
        .iter()
        .enumerate()
        .map(|(i, a)| format!("{} {a}", i + 1))
        .collect();
    let numbers: Vec<String> = (1..=candidates.len()).map(|n| n.to_string()).collect();
    if en {
        format!(
            "Did you mean {}? Reply with the number ({}), or address it with /{}.",
            numbered.join(" or "),
            numbers.join(" / "),
            candidates[0]
        )
    } else {
        format!(
            "你是想找 {}？回复 {}，或用 /别名（例如 /{}）。",
            numbered.join(" 还是 "),
            numbers.join(" 或 "),
            candidates[0]
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

/// The contact gate's client for the model gate's `/v1/systemone` relay.
pub struct JevClient {
    http: reqwest::Client,
    url: String,
    key: String,
}

impl JevClient {
    pub fn new(gate_url: &str, key: &str, timeout_ms: u64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms.max(100)))
            .build()
            .unwrap_or_default();
        Self {
            http,
            url: format!("{}{}", gate_url.trim_end_matches('/'), SYSTEMONE_ROUTE),
            key: key.to_string(),
        }
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
    use agentkeys_protocol::{SystemOneAnswer, SystemOneUsage};

    fn reach() -> Vec<String> {
        vec!["chef".into(), "storyteller".into()]
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

    #[test]
    fn request_options_are_exactly_reach_plus_unclear_with_last_agent_as_context() {
        let candidates: Vec<Candidate> = vec![
            (
                "chef".into(),
                Some(AppBlurb {
                    name: "Chef".into(),
                    purpose: "plans meals".into(),
                    examples: vec!["今晚吃什么".into()],
                    ..Default::default()
                }),
            ),
            ("storyteller".into(), None),
        ];
        let req = build_request("jev-1.13.0", "讲个故事", "kid", Some("chef"), &candidates);
        let SystemOneQuestion::Choice {
            criteria,
            instructions,
        } = &req.questions[DESTINATION_QUESTION]
        else {
            panic!("destination must be a choice");
        };
        let keys: Vec<&String> = criteria.keys().collect();
        assert_eq!(keys, vec!["chef", "storyteller", "unclear"]);
        assert_eq!(criteria["chef"]["purpose"], "plans meals");
        assert!(criteria["storyteller"].is_null());
        assert_eq!(req.state["message"], "讲个故事");
        assert_eq!(req.state["last_agent"], "chef");
        assert!(instructions.as_str().unwrap().contains("`last_agent`"));
        // No last agent → not in the state, not in the instructions.
        let req = build_request("jev-1.13.0", "hi", "kid", None, &candidates);
        assert!(req.state.get("last_agent").is_none());
        let SystemOneQuestion::Choice { instructions, .. } = &req.questions[DESTINATION_QUESTION]
        else {
            unreachable!()
        };
        assert!(!instructions.as_str().unwrap().contains("last_agent"));
    }

    #[test]
    fn confident_pick_routes_and_below_threshold_asks_with_ranked_candidates() {
        let r = response(
            "chef",
            &[("chef", 0.9), ("storyteller", 0.08), ("unclear", 0.02)],
            0.85,
        );
        assert_eq!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Route {
                alias: "chef".into(),
                confidence: 0.85
            }
        );
        let r = response(
            "storyteller",
            &[("chef", 0.4), ("storyteller", 0.45), ("unclear", 0.15)],
            0.2,
        );
        assert_eq!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Ask {
                candidates: vec!["storyteller".into(), "chef".into()],
                confidence: 0.2
            }
        );
        // `unclear` on top asks even when the vendor is confident about it.
        let r = response(
            "unclear",
            &[("chef", 0.1), ("storyteller", 0.1), ("unclear", 0.8)],
            0.7,
        );
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Ask { .. }
        ));
    }

    #[test]
    fn an_answer_outside_reach_is_malformed_never_a_route() {
        // The injection posture: even if the model (or a spoofed gate) names
        // an agent outside reach, the router never routes there.
        let r = response("admin", &[("admin", 0.99), ("chef", 0.01)], 0.99);
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Malformed(_)
        ));
        let r = response("chef", &[("chef", 0.5), ("banker", 0.5)], 0.9);
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Malformed(_)
        ));
        // A missing / wrong-typed answer is malformed too.
        let mut r = response("chef", &[("chef", 1.0)], 1.0);
        r.answers.clear();
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, None, 1.0),
            JevVerdict::Malformed(_)
        ));
    }

    #[test]
    fn last_agent_weight_leans_a_close_call_and_recomputes_confidence() {
        // Vendor: a near coin flip, slightly for storyteller. Weight 3 on chef
        // (the last agent) moves the peak to chef: adjusted chef 1.35/1.9 ≈ 0.71,
        // recomputed confidence (3·0.71 − 1)/2 ≈ 0.57 — an ask at 0.6, a route
        // at 0.5. Either way chef now leads.
        let r = response(
            "storyteller",
            &[("chef", 0.45), ("storyteller", 0.5), ("unclear", 0.05)],
            0.2,
        );
        match verdict_from(&r, &reach(), 0.6, Some("chef"), 3.0) {
            JevVerdict::Ask {
                candidates,
                confidence,
            } => {
                assert_eq!(candidates[0], "chef");
                assert!(confidence > 0.5 && confidence < 0.6, "{confidence}");
            }
            other => panic!("expected an ask, got {other:?}"),
        }
        assert!(matches!(
            verdict_from(&r, &reach(), 0.5, Some("chef"), 3.0),
            JevVerdict::Route { alias, .. } if alias == "chef"
        ));
        // A clear content signal beats the weight: «讲个故事» → storyteller.
        let r = response(
            "storyteller",
            &[("chef", 0.05), ("storyteller", 0.93), ("unclear", 0.02)],
            0.9,
        );
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, Some("chef"), 3.0),
            JevVerdict::Route { alias, .. } if alias == "storyteller"
        ));
        // Weight 1 = the vendor's numbers untouched.
        let r = response(
            "storyteller",
            &[("chef", 0.45), ("storyteller", 0.5), ("unclear", 0.05)],
            0.2,
        );
        assert!(matches!(
            verdict_from(&r, &reach(), 0.6, Some("chef"), 1.0),
            JevVerdict::Ask { confidence, .. } if confidence == 0.2
        ));
    }

    #[test]
    fn ask_replies_pick_by_number_name_or_slash_and_anything_else_is_a_new_message() {
        let c = vec!["chef".to_string(), "storyteller".to_string()];
        assert_eq!(parse_ask_reply("1", &c).as_deref(), Some("chef"));
        assert_eq!(parse_ask_reply(" ２ ", &c).as_deref(), Some("storyteller"));
        assert_eq!(
            parse_ask_reply("Storyteller", &c).as_deref(),
            Some("storyteller")
        );
        assert_eq!(parse_ask_reply("/chef", &c).as_deref(), Some("chef"));
        assert_eq!(parse_ask_reply("3", &c), None);
        assert_eq!(parse_ask_reply("0", &c), None);
        assert_eq!(parse_ask_reply("今晚吃什么", &c), None);
        assert_eq!(parse_ask_reply("1", &[]), None);
    }

    #[test]
    fn ask_text_names_the_candidates_numbered_in_both_languages() {
        let c = vec!["chef".to_string(), "storyteller".to_string()];
        assert_eq!(
            ask_text(&c, false),
            "你是想找 1 chef 还是 2 storyteller？回复 1 或 2，或用 /别名（例如 /chef）。"
        );
        assert_eq!(
            ask_text(&c, true),
            "Did you mean 1 chef or 2 storyteller? Reply with the number (1 / 2), or address it with /chef."
        );
        assert!(ask_text(&[], false).contains("/别名"));
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
