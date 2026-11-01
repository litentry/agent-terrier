use std::{path::Path, time::Duration};

use agentkeys_core::{chain_profile::is_loopback_http_endpoint, protected_file};
use agentkeys_protocol::ChannelWakeRequest;
use anyhow::{ensure, Result};
use zeroize::Zeroizing;

pub struct WakeClient {
    url: String,
    bearer: Zeroizing<String>,
    http: reqwest::Client,
}

impl WakeClient {
    pub fn local(url: String, token_file: &Path) -> Result<Self> {
        ensure!(
            is_loopback_http_endpoint(&url),
            "development wake endpoint must be on loopback"
        );
        let bearer = protected_file::read_token(token_file)?;
        Ok(Self {
            url,
            bearer,
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(20))
                .build()?,
        })
    }

    pub async fn wake(&self, request: &ChannelWakeRequest) -> Result<()> {
        let response = self
            .http
            .post(&self.url)
            .bearer_auth(&*self.bearer)
            .json(request)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "application wake returned HTTP {}",
            response.status()
        );
        Ok(())
    }
}
