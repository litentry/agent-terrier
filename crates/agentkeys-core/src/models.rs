use std::time::Duration;

use anyhow::{ensure, Context, Result};
use reqwest::{Response, Url};
use serde_json::Value;

pub mod qualification;

pub use agentkeys_protocol::model_config::{
    default_base_url, default_chat_model, default_embedding_model, local_recipe,
};

pub const CHAT_PATH: &str = "/chat/completions";
pub const EMBEDDINGS_PATH: &str = "/embeddings";
pub const MODEL_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
pub const MAX_MODEL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub fn base_url(value: &str) -> Result<Url> {
    agentkeys_protocol::model_config::base_url(value).map_err(anyhow::Error::msg)
}

pub fn require_local_endpoint(value: &str) -> Result<()> {
    agentkeys_protocol::model_config::require_local_endpoint(value).map_err(anyhow::Error::msg)
}

pub struct ModelClient {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
}

impl ModelClient {
    pub fn new(base_url: &str, api_key: Option<&str>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(MODEL_REQUEST_TIMEOUT)
                .build()
                .expect("model HTTP client"),
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key: api_key.filter(|key| !key.is_empty()).map(str::to_owned),
        }
    }

    pub async fn request(&self, path: &str, body: Option<&Value>) -> Result<Response> {
        let mut endpoint = base_url(&self.base_url)?;
        ensure!(
            path.starts_with('/') && !path.contains(['?', '#']) && !path.contains(".."),
            "invalid model API path"
        );
        endpoint.set_path(&format!(
            "{}{}",
            endpoint.path().trim_end_matches('/'),
            path
        ));
        let mut request = match body {
            Some(body) => self.http.post(endpoint).json(body),
            None => self.http.get(endpoint),
        };
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }
        request.send().await.map_err(|_| anyhow::anyhow!("model service unavailable or request timed out; check the configured endpoint and runner logs"))
    }

    pub async fn chat(&self, body: &Value) -> Result<Response> {
        self.request(CHAT_PATH, Some(body)).await
    }
    pub async fn embeddings(&self, body: &Value) -> Result<Response> {
        self.request(EMBEDDINGS_PATH, Some(body)).await
    }
    pub async fn models(&self) -> Result<Response> {
        self.request("/models", None).await
    }
}

pub async fn response_json(mut response: Response) -> Result<Value> {
    ensure!(response.status().is_success(), "model service returned HTTP {}; check model availability, supported capabilities and available memory", response.status().as_u16());
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_MODEL_RESPONSE_BYTES,
            "model response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("model service returned malformed JSON")
}
