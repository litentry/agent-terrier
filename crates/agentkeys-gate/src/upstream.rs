//! The one upstream the relay fronts — an OpenAI-compatible server (Ark). The
//! relay holds the vendor key; callers never see it. No retry, no fallback, no
//! caching (arch.md §22d discipline).

use serde_json::Value;

use crate::config::UpstreamConfig;
use crate::error::{GateError, GateResult};

/// The upstream paths the relay calls — also the `route` its refusal logs name.
pub const CHAT_PATH: &str = "/chat/completions";

pub fn embeddings_path(multimodal: bool) -> &'static str {
    if multimodal {
        "/embeddings/multimodal"
    } else {
        "/embeddings"
    }
}

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
            .post(format!("{}{CHAT_PATH}", self.base_url))
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }

    /// POST the embeddings body (#572). Same custody as chat: the vendor key
    /// is attached here, never held by the caller (the in-sandbox OpenViking
    /// engine sends its `gk_` relay key to the gate instead). `multimodal`
    /// selects Ark's `/embeddings/multimodal` twin (#639 — the surface the
    /// doubao-embedding-vision endpoint serves and OpenViking 0.4.16 calls;
    /// the text `/embeddings` API is refused by that model family, measured
    /// 2026-08-26).
    pub async fn embeddings(
        &self,
        body: &Value,
        multimodal: bool,
    ) -> GateResult<reqwest::Response> {
        self.client
            .post(format!("{}{}", self.base_url, embeddings_path(multimodal)))
            .bearer_auth(&self.api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }

    /// #653 — GET the SearXNG JSON API. No credential: the search upstream is
    /// the broker-host loopback SearXNG, and the ENGINE SET (pinned by the
    /// gate's config, never the caller) is the policy surface.
    pub async fn search_get(
        client: &reqwest::Client,
        base_url: &str,
        q: &str,
        engines: &str,
        language: Option<&str>,
    ) -> GateResult<reqwest::Response> {
        let mut req = client.get(format!("{base_url}/search")).query(&[
            ("q", q),
            ("format", "json"),
            ("engines", engines),
        ]);
        if let Some(lang) = language.filter(|l| !l.trim().is_empty()) {
            req = req.query(&[("language", lang)]);
        }
        req.send()
            .await
            .map_err(|e| GateError::Upstream(format!("search upstream transport: {e}")))
    }

    /// #722 — POST a System One request to TypeSafe (`<base>/v1/systemone`).
    /// The gate-held TypeSafe key rides here; the caller only ever presented
    /// its `gk_` relay key. No retry, no fallback — the caller (the contact
    /// gate's router) owns the deterministic fallback.
    pub async fn systemone_post(
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
        body: &Value,
    ) -> GateResult<reqwest::Response> {
        client
            .post(format!(
                "{}{}",
                base_url.trim_end_matches('/'),
                agentkeys_protocol::SYSTEMONE_ROUTE
            ))
            .bearer_auth(api_key)
            .json(body)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("systemone upstream transport: {e}")))
    }

    /// #722 — GET `<base>/v1/models` on the System One server: Kev reports its
    /// revision and sampling temperature there. The gate-held key rides here.
    pub async fn systemone_models_get(
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
    ) -> GateResult<reqwest::Response> {
        client
            .get(format!("{}/v1/models", base_url.trim_end_matches('/')))
            .bearer_auth(api_key)
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("systemone upstream transport: {e}")))
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
