//! What an upstream non-2xx says, and whose problem it is.
//!
//! Measured on VE prod 2026-09-29: an overdue Volcano Engine account makes Ark
//! answer HTTP 403 `AccountOverdueError` to EVERY call — `/chat/completions`
//! and `/embeddings/multimodal` alike, whatever relay key sent it — while
//! `GET /models` still answers 200. The gate logged each refusal as a per-key
//! `upstream 4xx forwarded key=… status=403` with no route, model or code, so
//! two stack-wide outages (2026-09-21, 2026-09-28) read as one delegate's
//! embedding problem: the only key calling steadily was the one in the log.
//!
//! So every forwarded refusal now carries the upstream's own `code` and
//! `message`, and an ACCOUNT-scoped code is an operator alarm (ERROR +
//! `/readyz` 503), never a caller fault. The standing refusal clears on the
//! next upstream 2xx — there is no free probe (`/models` answers 200 while
//! the account is refused), so it is the next real call that proves recovery.

use std::sync::Mutex;

use serde::Serialize;
use serde_json::Value;

/// Upstream error codes that refuse the whole ACCOUNT — every caller, every
/// model — so the fix is the operator's (billing), never the caller's. Add a
/// code only with the same evidence: an answer measured on a live stack.
pub const ACCOUNT_SCOPED_CODES: &[&str] = &[
    // Ark, measured 2026-09-29 on VE prod (403, `type: Forbidden`).
    "AccountOverdueError",
];

/// The upstream message is logged, never trusted to be short.
const MESSAGE_LOG_CHARS: usize = 300;

/// The `{"error": {code, message, type}}` envelope of an upstream refusal,
/// read permissively (a proxy's HTML page still yields a logged message).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpstreamErrorDetail {
    pub code: Option<String>,
    pub kind: Option<String>,
    pub message: String,
}

impl UpstreamErrorDetail {
    pub fn parse(body: &[u8]) -> Self {
        let text_of = |v: &Value, key: &str| {
            v.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        };
        match serde_json::from_slice::<Value>(body) {
            Ok(v) if v.is_object() => {
                let envelope = v.get("error").filter(|e| e.is_object()).unwrap_or(&v);
                Self {
                    code: text_of(envelope, "code"),
                    kind: text_of(envelope, "type"),
                    message: truncate_chars(
                        &text_of(envelope, "message").unwrap_or_default(),
                        MESSAGE_LOG_CHARS,
                    ),
                }
            }
            _ => Self {
                code: None,
                kind: None,
                message: truncate_chars(String::from_utf8_lossy(body).trim(), MESSAGE_LOG_CHARS),
            },
        }
    }

    pub fn is_account_scoped(&self) -> bool {
        self.code
            .as_deref()
            .is_some_and(|c| ACCOUNT_SCOPED_CODES.contains(&c))
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max).collect();
    format!("{cut}…")
}

/// The standing account-scoped refusal: the latest upstream answer refused the
/// account. Public on `/readyz` — the upstream's code and when, never its
/// message or the model the caller named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountRefusal {
    pub code: String,
    pub status: u16,
    /// The upstream path that was refused (`/chat/completions`, …).
    pub route: String,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub refusals: u64,
}

#[derive(Debug, Default)]
pub struct UpstreamAccountState {
    standing: Mutex<Option<AccountRefusal>>,
}

impl UpstreamAccountState {
    /// Record an account-scoped refusal; returns the standing record.
    pub fn refused(&self, code: &str, status: u16, route: &str, now_unix: u64) -> AccountRefusal {
        let mut standing = self.standing.lock().unwrap_or_else(|p| p.into_inner());
        let next = match standing.take() {
            Some(mut r) => {
                r.code = code.to_string();
                r.status = status;
                r.route = route.to_string();
                r.last_seen_unix = now_unix;
                r.refusals += 1;
                r
            }
            None => AccountRefusal {
                code: code.to_string(),
                status,
                route: route.to_string(),
                first_seen_unix: now_unix,
                last_seen_unix: now_unix,
                refusals: 1,
            },
        };
        *standing = Some(next.clone());
        next
    }

    /// The upstream answered 2xx: any standing refusal is over. Returns the
    /// record it cleared, so the caller can log the recovery once.
    pub fn answered(&self) -> Option<AccountRefusal> {
        self.standing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    pub fn current(&self) -> Option<AccountRefusal> {
        self.standing
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body Ark answered on VE prod 2026-09-29 (chat and embeddings alike).
    const ARK_OVERDUE: &str = r#"{"error":{"code":"AccountOverdueError","message":"The request failed because your account has an overdue balance. Request id: 021790685392088bfe35b6525b6a24c7ddbea7b420bd5585f179e","param":"","type":"Forbidden"}}"#;

    #[test]
    fn the_measured_ark_overdue_body_is_an_account_refusal() {
        let d = UpstreamErrorDetail::parse(ARK_OVERDUE.as_bytes());
        assert_eq!(d.code.as_deref(), Some("AccountOverdueError"));
        assert_eq!(d.kind.as_deref(), Some("Forbidden"));
        assert!(d
            .message
            .starts_with("The request failed because your account"));
        assert!(d.is_account_scoped());
    }

    #[test]
    fn a_request_refusal_is_not_the_accounts() {
        let d = UpstreamErrorDetail::parse(
            br#"{"error":{"code":"InvalidParameter","message":"model not found","type":"BadRequest"}}"#,
        );
        assert_eq!(d.code.as_deref(), Some("InvalidParameter"));
        assert!(!d.is_account_scoped());
        let d = UpstreamErrorDetail::parse(
            br#"{"error":{"message":"model not found","type":"invalid_request_error"}}"#,
        );
        assert_eq!(d.code, None);
        assert_eq!(d.message, "model not found");
        assert!(!d.is_account_scoped());
    }

    #[test]
    fn a_non_json_body_still_logs_bounded() {
        let page = format!("<html>{}</html>", "x".repeat(1000));
        let d = UpstreamErrorDetail::parse(page.as_bytes());
        assert_eq!(d.code, None);
        assert!(d.message.starts_with("<html>"));
        assert_eq!(d.message.chars().count(), MESSAGE_LOG_CHARS + 1);
        assert!(!d.is_account_scoped());
    }

    #[test]
    fn a_standing_refusal_counts_until_the_upstream_answers() {
        let state = UpstreamAccountState::default();
        assert_eq!(state.current(), None);
        state.refused("AccountOverdueError", 403, "/embeddings/multimodal", 100);
        let r = state.refused("AccountOverdueError", 403, "/chat/completions", 160);
        assert_eq!(r.first_seen_unix, 100);
        assert_eq!(r.last_seen_unix, 160);
        assert_eq!(r.refusals, 2);
        assert_eq!(r.route, "/chat/completions");
        assert_eq!(state.current(), Some(r.clone()));
        assert_eq!(state.answered(), Some(r));
        assert_eq!(state.current(), None);
        assert_eq!(state.answered(), None);
    }
}
