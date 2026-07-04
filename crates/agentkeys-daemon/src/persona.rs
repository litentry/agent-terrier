//! #390 — persona (`SOUL.md`) edit-time validation + durable version rotation.
//!
//! Persona is the strictest context kind (master-hub-topology.md §16 / arch.md
//! §5 "context system"): master-authored only (never inbox-adoptable), applied
//! fresh each agent turn, validated at EDIT time — the sandbox apply leg never
//! re-validates, so nothing invalid may enter canonical. The document lives in
//! the reserved `persona` memory namespace as the per-delegate key
//! `soul:<omni>` (current) plus `soul:<omni>@<n>` history entries (rollback,
//! §16.2 item 5). This module owns the pure policy — the `ui_bridge` handlers
//! own transport/storage.

use crate::ui_bridge::{ContextKind, StoredMemoryEntry};

/// Edit-time size cap for a persona document. `SOUL.md` ships at ~2 KiB; the
/// cap bounds prompt-cache bloat and blocks accidental file-dump pastes.
pub(crate) const PERSONA_MAX_BYTES: usize = 32 * 1024;

/// How many superseded persona versions are kept for rollback (§16.2 item 5).
pub(crate) const PERSONA_HISTORY_KEEP: usize = 5;

/// Validate a persona body at EDIT time (§16.2 item 3): non-empty, the
/// [`PERSONA_MAX_BYTES`] cap, no secret-shaped content, and the agent-agnostic
/// guardrail — the persona must never claim to BE AgentKeys (AgentKeys is the
/// key/permission layer; the agent is e.g. Hermes). The scans are best-effort
/// linters over known shapes, not a DLP guarantee — they catch the honest
/// mistakes (pasting a key file, cargo-culting "I am AgentKeys" from a doc).
pub(crate) fn validate_persona_body(body: &str) -> Result<(), String> {
    if body.trim().is_empty() {
        return Err("persona_empty: the persona document cannot be empty".into());
    }
    if body.len() > PERSONA_MAX_BYTES {
        return Err(format!(
            "persona_too_large: {} bytes exceeds the {PERSONA_MAX_BYTES}-byte persona cap",
            body.len()
        ));
    }
    if let Some(what) = find_secret_shape(body) {
        return Err(format!(
            "persona_secret_shaped: the document contains {what} — persona files are \
             distributed to the agent runtime and must never carry secrets"
        ));
    }
    let lower = body.to_lowercase();
    for claim in [
        "you are agentkeys",
        "i am agentkeys",
        "your name is agentkeys",
    ] {
        if lower.contains(claim) {
            return Err(format!(
                "persona_identity_claim: found `{claim}` — the persona must never claim to \
                 BE AgentKeys (AgentKeys is the key/permission layer; the agent is the \
                 assistant, e.g. Hermes)"
            ));
        }
    }
    Ok(())
}

/// Scan for secret-shaped substrings: AWS access-key ids, PEM private-key
/// headers, `sk-`-style API keys, and 32-byte hex (EVM private keys). Returns
/// a human label for the first match. Hand-rolled (no regex dep in the daemon).
fn find_secret_shape(body: &str) -> Option<&'static str> {
    if body.contains("PRIVATE KEY") && body.contains("-----BEGIN") {
        return Some("a PEM private-key block");
    }
    let bytes = body.as_bytes();
    let run_of = |start: usize, pred: fn(u8) -> bool| -> usize {
        bytes[start..].iter().take_while(|b| pred(**b)).count()
    };
    let is_upper_alnum = |b: u8| b.is_ascii_uppercase() || b.is_ascii_digit();
    let is_alnum_keyish = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_';
    let is_hex = |b: u8| b.is_ascii_hexdigit();
    for (i, w) in body.as_bytes().windows(4).enumerate() {
        if w == b"AKIA" && run_of(i + 4, is_upper_alnum) >= 16 {
            return Some("an AWS access-key id (AKIA…)");
        }
    }
    for (i, w) in body.as_bytes().windows(3).enumerate() {
        // `sk-` followed by a long key-shaped run (OpenAI/Ark-style secrets).
        if w == b"sk-" && run_of(i + 3, is_alnum_keyish) >= 20 {
            return Some("an `sk-…` API key");
        }
    }
    for (i, w) in body.as_bytes().windows(2).enumerate() {
        if w == b"0x" && run_of(i + 2, is_hex) >= 64 {
            return Some("a 32-byte hex value (EVM private-key shaped)");
        }
    }
    None
}

/// Parse a persona entry version (`"v3"`, tolerating a bare `"3"`); 0 when
/// unparseable (pre-#390 fabricated versions sort below every real one).
pub(crate) fn parse_version(v: &str) -> u32 {
    v.strip_prefix('v').unwrap_or(v).parse().unwrap_or(0)
}

/// The history-key prefix for one delegate's superseded persona versions.
fn history_prefix(soul_key: &str) -> String {
    format!("{soul_key}@")
}

/// Split a persona-namespace array into (others, current, history) for one
/// delegate's `soul_key`. `others` = every entry belonging to OTHER delegates
/// (preserved verbatim by rotation).
fn split_persona(
    entries: Vec<StoredMemoryEntry>,
    soul_key: &str,
) -> (
    Vec<StoredMemoryEntry>,
    Option<StoredMemoryEntry>,
    Vec<StoredMemoryEntry>,
) {
    let prefix = history_prefix(soul_key);
    let mut others = Vec::new();
    let mut current = None;
    let mut history = Vec::new();
    for e in entries {
        if e.key == soul_key {
            current = Some(e);
        } else if e.key.starts_with(&prefix) {
            history.push(e);
        } else {
            others.push(e);
        }
    }
    (others, current, history)
}

/// Rotate one delegate's persona to `new_body` (§16.2 item 5): the current
/// document (if any) moves into history as `<soul_key>@<its-version>`, history
/// is pruned to the newest [`PERSONA_HISTORY_KEEP`], and the new current gets
/// version `v<max+1>`. Entries of other delegates pass through untouched.
/// Returns the rewritten namespace array + the new version number.
pub(crate) fn rotate_persona(
    entries: Vec<StoredMemoryEntry>,
    soul_key: &str,
    new_body: &str,
    updated: &str,
) -> (Vec<StoredMemoryEntry>, u32) {
    let (mut out, current, mut history) = split_persona(entries, soul_key);
    let max_seen = current
        .iter()
        .chain(history.iter())
        .map(|e| parse_version(&e.version))
        .max()
        .unwrap_or(0);
    let next = max_seen + 1;
    if let Some(mut cur) = current {
        cur.key = format!(
            "{}{}",
            history_prefix(soul_key),
            parse_version(&cur.version)
        );
        history.push(cur);
    }
    history.sort_by_key(|e| std::cmp::Reverse(parse_version(&e.version)));
    history.truncate(PERSONA_HISTORY_KEEP);
    out.extend(history);
    out.push(StoredMemoryEntry {
        key: soul_key.to_string(),
        title: "SOUL.md".to_string(),
        body: new_body.to_string(),
        updated: updated.to_string(),
        bytes: new_body.len() as u64,
        version: format!("v{next}"),
        kind: ContextKind::Persona,
    });
    out.sort_by(|a, b| a.key.cmp(&b.key));
    (out, next)
}

/// The body of one delegate's persona at `version` — current or history —
/// for the rollback verb. `None` when that version is gone (pruned or never
/// existed).
pub(crate) fn persona_body_for_version(
    entries: &[StoredMemoryEntry],
    soul_key: &str,
    version: u32,
) -> Option<String> {
    let prefix = history_prefix(soul_key);
    entries
        .iter()
        .filter(|e| e.key == soul_key || e.key.starts_with(&prefix))
        .find(|e| parse_version(&e.version) == version)
        .map(|e| e.body.clone())
}

/// One delegate's (current, history-desc) view of the persona namespace, for
/// the editor's GET.
pub(crate) fn persona_view(
    entries: Vec<StoredMemoryEntry>,
    soul_key: &str,
) -> (Option<StoredMemoryEntry>, Vec<StoredMemoryEntry>) {
    let (_others, current, mut history) = split_persona(entries, soul_key);
    history.sort_by_key(|e| std::cmp::Reverse(parse_version(&e.version)));
    (current, history)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, body: &str, version: &str) -> StoredMemoryEntry {
        StoredMemoryEntry {
            key: key.into(),
            title: "SOUL.md".into(),
            body: body.into(),
            updated: "2026-07-04".into(),
            bytes: body.len() as u64,
            version: version.into(),
            kind: ContextKind::Persona,
        }
    }

    #[test]
    fn validation_rejects_empty_oversize_secrets_and_identity_claims() {
        assert!(validate_persona_body("  \n ").is_err());
        assert!(validate_persona_body(&"x".repeat(PERSONA_MAX_BYTES + 1)).is_err());
        assert!(validate_persona_body("key: AKIAABCDEFGHIJKLMNOP").is_err());
        assert!(validate_persona_body("-----BEGIN EC PRIVATE KEY-----\nabc").is_err());
        assert!(validate_persona_body(&format!("token sk-{}", "a".repeat(24))).is_err());
        assert!(validate_persona_body(&format!("wallet 0x{}", "ab".repeat(32))).is_err());
        assert!(validate_persona_body("You are AgentKeys, the assistant.").is_err());
        // The legit framing survives: working WITH AgentKeys is the documented
        // relationship (agent-terrier.md); claiming to BE it is what's blocked.
        assert!(validate_persona_body("You work with AgentKeys; it holds the keys.").is_ok());
        assert!(validate_persona_body("Speak in short sentences. 说中文也可以。").is_ok());
        // A short hex address (20 bytes) is not private-key shaped.
        assert!(validate_persona_body(&format!("addr 0x{}", "ab".repeat(20))).is_ok());
    }

    #[test]
    fn rotation_moves_current_to_history_and_bumps_version() {
        let soul = "soul:0xabc";
        // First edit on an empty namespace → v1, no history.
        let (v1, n1) = rotate_persona(Vec::new(), soul, "be warm", "d1");
        assert_eq!(n1, 1);
        assert_eq!(v1.len(), 1);
        assert_eq!(v1[0].key, soul);
        assert_eq!(v1[0].version, "v1");
        assert_eq!(v1[0].kind, ContextKind::Persona);

        // Second edit → current v2, v1 preserved as history.
        let (v2, n2) = rotate_persona(v1, soul, "be concise", "d2");
        assert_eq!(n2, 2);
        let cur = v2.iter().find(|e| e.key == soul).unwrap();
        assert_eq!(
            (cur.version.as_str(), cur.body.as_str()),
            ("v2", "be concise")
        );
        let hist = v2.iter().find(|e| e.key == format!("{soul}@1")).unwrap();
        assert_eq!(hist.body, "be warm");
    }

    #[test]
    fn rotation_prunes_history_and_preserves_other_delegates() {
        let soul = "soul:0xabc";
        let other = entry("soul:0xdef", "other delegate", "v9");
        let mut entries = vec![other.clone()];
        for i in 1..=(PERSONA_HISTORY_KEEP + 3) {
            let (next, _) = rotate_persona(entries, soul, &format!("body {i}"), "d");
            entries = next;
        }
        let hist_count = entries
            .iter()
            .filter(|e| e.key.starts_with("soul:0xabc@"))
            .count();
        assert_eq!(hist_count, PERSONA_HISTORY_KEEP);
        // The oldest versions were pruned; the other delegate's entry survived.
        assert!(entries
            .iter()
            .any(|e| e.key == other.key && e.body == other.body));
        assert!(persona_body_for_version(&entries, soul, 1).is_none());
    }

    #[test]
    fn rollback_body_resolves_current_and_history_versions() {
        let soul = "soul:0xabc";
        let (e1, _) = rotate_persona(Vec::new(), soul, "one", "d");
        let (e2, _) = rotate_persona(e1, soul, "two", "d");
        assert_eq!(
            persona_body_for_version(&e2, soul, 1).as_deref(),
            Some("one")
        );
        assert_eq!(
            persona_body_for_version(&e2, soul, 2).as_deref(),
            Some("two")
        );
        assert!(persona_body_for_version(&e2, soul, 3).is_none());
        let (cur, hist) = persona_view(e2, soul);
        assert_eq!(cur.unwrap().body, "two");
        assert_eq!(hist.len(), 1);
    }
}
