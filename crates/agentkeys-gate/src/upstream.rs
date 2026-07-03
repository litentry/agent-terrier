//! The one upstream the relay fronts — an OpenAI-compatible server (Ark). The
//! relay holds the vendor key; callers never see it. No retry, no fallback, no
//! caching (arch.md §22d discipline).

use serde_json::Value;

use crate::config::UpstreamConfig;
use crate::error::{GateError, GateResult};

pub struct UpstreamClient {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
}

impl UpstreamClient {
    pub fn new(cfg: &UpstreamConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: cfg.base_url.clone(),
            api_key: cfg.api_key.clone(),
        }
    }

    /// POST the (already relay-adjusted) chat-completions body. Returns the
    /// raw response — the caller owns status triage and (for streams) the tee.
    pub async fn chat(&self, body: &Value) -> GateResult<reqwest::Response> {
        self.client
            .post(format!("{}/chat/completions", self.base_url))
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }

    /// GET /models passthrough (OpenAI clients often list models at boot).
    pub async fn models(&self) -> GateResult<reqwest::Response> {
        self.client
            .get(format!("{}/models", self.base_url))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }
}
