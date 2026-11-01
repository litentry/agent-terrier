//! Model transport shared with the local CLI, without retries or fallback.

use serde_json::Value;

use crate::config::UpstreamConfig;
use crate::error::{GateError, GateResult};

/// The upstream paths the relay calls — also the `route` its refusal logs name.
pub use agentkeys_core::models::CHAT_PATH;

/// How long one provider's `/v1/models` may take inside the models report
/// (the contact gate gives the whole report 3 s).
pub const SYSTEMONE_MODELS_TIMEOUT_MS: u64 = 2500;

pub fn embeddings_path(multimodal: bool) -> &'static str {
    if multimodal {
        "/embeddings/multimodal"
    } else {
        agentkeys_core::models::EMBEDDINGS_PATH
    }
}

pub struct UpstreamClient {
    client: agentkeys_core::models::ModelClient,
}

impl UpstreamClient {
    pub fn new(cfg: &UpstreamConfig) -> Self {
        Self {
            client: agentkeys_core::models::ModelClient::new(&cfg.base_url, Some(&cfg.api_key)),
        }
    }

    /// POST the (already relay-adjusted) chat-completions body. Returns the
    /// raw response — the caller owns status triage and (for streams) the tee.
    pub async fn chat(&self, body: &Value) -> GateResult<reqwest::Response> {
        self.client
            .chat(body)
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }

    /// The optional multimodal route is forwarded only when explicitly requested.
    pub async fn embeddings(
        &self,
        body: &Value,
        multimodal: bool,
    ) -> GateResult<reqwest::Response> {
        self.client
            .request(embeddings_path(multimodal), Some(body))
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

    /// #722 — POST a System One request to a decision-model provider
    /// (`<base>/v1/systemone` — TypeSafe for Jev, the Kev server for Kev). The
    /// gate-held provider key rides here; the caller only ever presented its
    /// `gk_` relay key. No retry, no fallback — the caller (the contact gate's
    /// router) owns the deterministic fallback.
    pub async fn systemone_post(
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
        body: &Value,
    ) -> GateResult<reqwest::Response> {
        let request = client
            .post(format!(
                "{}{}",
                base_url.trim_end_matches('/'),
                agentkeys_protocol::SYSTEMONE_ROUTE
            ))
            .json(body);
        let request = if api_key.is_empty() {
            request
        } else {
            request.bearer_auth(api_key)
        };
        request
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("systemone upstream transport: {e}")))
    }

    /// #722 — GET `<base>/v1/models` on a System One server: Kev reports its
    /// revision and sampling temperature there, TypeSafe its model aliases.
    /// The gate-held key rides here. Bounded: a report, never a turn.
    pub async fn systemone_models_get(
        client: &reqwest::Client,
        base_url: &str,
        api_key: &str,
    ) -> GateResult<reqwest::Response> {
        let request = client
            .get(format!("{}/v1/models", base_url.trim_end_matches('/')))
            .timeout(std::time::Duration::from_millis(
                SYSTEMONE_MODELS_TIMEOUT_MS,
            ));
        let request = if api_key.is_empty() {
            request
        } else {
            request.bearer_auth(api_key)
        };
        request
            .send()
            .await
            .map_err(|e| GateError::Upstream(format!("systemone upstream transport: {e}")))
    }

    /// GET /models passthrough (OpenAI clients often list models at boot).
    pub async fn models(&self) -> GateResult<reqwest::Response> {
        self.client
            .models()
            .await
            .map_err(|e| GateError::Upstream(format!("upstream transport: {e}")))
    }
}
