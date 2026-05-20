//! Shared worker state — AWS SES + S3 clients.

use std::sync::Arc;

use aws_sdk_s3::Client as S3Client;
use aws_sdk_sesv2::Client as SesClient;

pub struct State {
    pub ses: SesClient,
    pub s3: S3Client,
    /// S3 bucket holding the per-actor inbox at bots/<actor_omni_hex>/inbound/.
    pub inbox_bucket: String,
}

impl State {
    pub async fn new(inbox_bucket: String) -> anyhow::Result<Self> {
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;
        Ok(Self {
            ses: SesClient::new(&cfg),
            s3: S3Client::new(&cfg),
            inbox_bucket,
        })
    }
}

pub type SharedState = Arc<State>;
