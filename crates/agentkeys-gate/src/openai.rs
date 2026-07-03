//! The slice of the OpenAI wire the relay actually touches.
//!
//! The relay is a passthrough — requests and responses stay `serde_json::Value`
//! / raw bytes so vendor-specific fields ride through untouched. Typed here are
//! only (a) the error envelope the relay emits itself and (b) the `usage`
//! counters it meters (#332), including the separately-priced `cached_tokens`
//! and `reasoning_tokens` details.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// OpenAI-shaped error envelope returned to the caller on relay-side failure,
/// so the caller's OpenAI client parses relay errors like upstream errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub message: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ApiError {
    pub fn new(kind: &str, message: impl Into<String>) -> Self {
        Self {
            error: ApiErrorBody {
                message: message.into(),
                kind: kind.to_string(),
                code: None,
            },
        }
    }
}

/// One turn's token counters, straight off the upstream `usage` object.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageCounters {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub cached_tokens: u64,
    pub reasoning_tokens: u64,
}

fn u64_at(v: &Value, path: &[&str]) -> u64 {
    let mut cur = v;
    for key in path {
        match cur.get(key) {
            Some(next) => cur = next,
            None => return 0,
        }
    }
    cur.as_u64().unwrap_or(0)
}

/// Extract usage counters from a chat-completion response (or a single SSE
/// chunk) JSON value. Returns `None` when there is no non-null `usage` object.
pub fn extract_usage(v: &Value) -> Option<UsageCounters> {
    let usage = v.get("usage")?;
    if usage.is_null() {
        return None;
    }
    Some(UsageCounters {
        prompt_tokens: u64_at(usage, &["prompt_tokens"]),
        completion_tokens: u64_at(usage, &["completion_tokens"]),
        total_tokens: u64_at(usage, &["total_tokens"]),
        cached_tokens: u64_at(usage, &["prompt_tokens_details", "cached_tokens"]),
        reasoning_tokens: u64_at(usage, &["completion_tokens_details", "reasoning_tokens"]),
    })
}

/// Incremental SSE scanner: feed forwarded chunks as-is, and it captures the
/// last non-null `usage` object seen (Ark puts it in the final data chunk when
/// `stream_options.include_usage` is set — the relay injects that; #332).
/// Handles `data:` lines split across chunk boundaries.
#[derive(Default)]
pub struct SseUsageScanner {
    line_buf: Vec<u8>,
    usage: Option<UsageCounters>,
}

impl SseUsageScanner {
    pub fn feed(&mut self, chunk: &[u8]) {
        for &b in chunk {
            if b == b'\n' {
                self.take_line();
            } else {
                self.line_buf.push(b);
            }
        }
    }

    fn take_line(&mut self) {
        let line = std::mem::take(&mut self.line_buf);
        let line = String::from_utf8_lossy(&line);
        let line = line.trim_end_matches('\r').trim();
        let Some(payload) = line.strip_prefix("data:") else {
            return;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            return;
        }
        if let Ok(v) = serde_json::from_str::<Value>(payload) {
            if let Some(u) = extract_usage(&v) {
                self.usage = Some(u);
            }
        }
    }

    /// Finalize (flushes a trailing unterminated line) and return the captured
    /// usage, if any.
    pub fn into_usage(mut self) -> Option<UsageCounters> {
        self.take_line();
        self.usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_usage_reads_details() {
        let resp = json!({
            "id": "x", "choices": [],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 40,
                "total_tokens": 140,
                "prompt_tokens_details": {"cached_tokens": 60},
                "completion_tokens_details": {"reasoning_tokens": 15}
            }
        });
        let u = extract_usage(&resp).unwrap();
        assert_eq!(u.prompt_tokens, 100);
        assert_eq!(u.completion_tokens, 40);
        assert_eq!(u.total_tokens, 140);
        assert_eq!(u.cached_tokens, 60);
        assert_eq!(u.reasoning_tokens, 15);
    }

    #[test]
    fn extract_usage_absent_or_null_is_none() {
        assert!(extract_usage(&json!({"id": "x"})).is_none());
        assert!(extract_usage(&json!({"usage": null})).is_none());
    }

    #[test]
    fn sse_scanner_captures_final_usage_across_split_chunks() {
        let mut s = SseUsageScanner::default();
        s.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}],\"usage\":null}\n\n");
        // The usage chunk arrives split across two network chunks.
        s.feed(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_");
        s.feed(b"tokens\":3,\"total_tokens\":10}}\n\ndata: [DONE]\n\n");
        let u = s.into_usage().unwrap();
        assert_eq!(u.total_tokens, 10);
        assert_eq!(u.prompt_tokens, 7);
    }

    #[test]
    fn sse_scanner_handles_crlf_and_trailing_line() {
        let mut s = SseUsageScanner::default();
        s.feed(
            b"data: {\"usage\":{\"total_tokens\":5,\"prompt_tokens\":5,\"completion_tokens\":0}}\r",
        );
        assert_eq!(s.into_usage().unwrap().total_tokens, 5);
    }
}
