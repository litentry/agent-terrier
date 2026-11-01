use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::protocol::{
    is_valid_resource_id, service_channel_pub, service_channel_sub, CapMintOp, ChannelDirection,
    ChannelEventKind, ChannelPollBody, ChannelPublishBody,
};
use agentkeys_backend_client::{BackendClient, CapMintRequest};
use agentkeys_core::device_crypto::DeviceKey;
use agentkeys_web_core::broker::{BrokerError, ChannelWorkerClient};
use anyhow::{anyhow, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::{local_data, CommandContext};

const MAX_TEXT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ChannelAction {
    Publish,
    Poll,
}

#[derive(clap::Args)]
pub struct ChannelOptions {
    pub action: ChannelAction,
    pub channel: String,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
    #[arg(long)]
    pub channel_url: String,
    #[arg(long)]
    pub text_stdin: bool,
    #[arg(long, default_value = "")]
    pub after: String,
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=25))]
    pub wait_seconds: u64,
}

fn worker_error(error: BrokerError) -> anyhow::Error {
    match error {
        BrokerError::Rejected { status, .. } => {
            anyhow!("local channel request failed (HTTP {status})")
        }
        BrokerError::Transport(_) => anyhow!("local channel service is unreachable"),
        BrokerError::Decode(_) => anyhow!("local channel response is invalid"),
    }
}

pub async fn execute(context: &CommandContext, options: &ChannelOptions) -> Result<Value> {
    let development = context.development_signing()?;
    development.require_local_service(&options.broker_url)?;
    development.require_local_service(&options.channel_url)?;
    ensure!(
        is_valid_resource_id(&options.channel),
        "invalid channel identifier"
    );
    ensure!(
        matches!(options.action, ChannelAction::Publish) == options.text_stdin,
        "only channel publish requires --text-stdin"
    );
    ensure!(
        options.after.len() <= 1024 && !options.after.chars().any(char::is_control),
        "invalid channel cursor"
    );
    ensure!(
        matches!(options.action, ChannelAction::Poll)
            || (options.after.is_empty() && options.wait_seconds == 0),
        "cursor and wait options require channel poll"
    );
    let mut text = String::new();
    if options.text_stdin {
        std::io::stdin()
            .take(MAX_TEXT_BYTES + 1)
            .read_to_string(&mut text)?;
        ensure!(
            !text.is_empty() && text.len() as u64 <= MAX_TEXT_BYTES,
            "channel text must contain 1 to {MAX_TEXT_BYTES} UTF-8 bytes"
        );
    }
    let key = Arc::new(
        DeviceKey::load(&options.device_key_file).context("load existing owner request key")?,
    );
    let session = local_data::load_session(
        &options.session_file,
        &options.broker_url,
        &options.operator_omni,
        &key,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(35))
        .build()?;
    let broker = BackendClient::with_client(
        http.clone(),
        Some(options.broker_url.clone()),
        None,
        None,
        None,
    )
    .with_device_key(key.clone());
    let worker = ChannelWorkerClient::with_client(http, &options.channel_url);
    let (operation, service) = match options.action {
        ChannelAction::Publish => (
            CapMintOp::ChannelPublish,
            service_channel_pub(&options.channel),
        ),
        ChannelAction::Poll => (
            CapMintOp::ChannelSubscribe,
            service_channel_sub(&options.channel),
        ),
    };
    let cap = broker
        .cap_mint(
            operation,
            CapMintRequest {
                operator_omni: options.operator_omni.clone(),
                actor_omni: options.operator_omni.clone(),
                device_key_hash: key.device_key_hash()?,
                service,
                ttl_seconds: local_data::CAPABILITY_TTL_SECONDS,
            },
            &session.session.session_jwt,
        )
        .await
        .map_err(|error| local_data::request_error(error.into(), "channel"))?;
    let response = match options.action {
        ChannelAction::Publish => serde_json::to_value(
            worker
                .publish(&ChannelPublishBody {
                    cap,
                    kind: ChannelEventKind::Text,
                    direction: ChannelDirection::In,
                    body_b64: Some(STANDARD.encode(text.as_bytes())),
                    body_ref: None,
                    correlation: None,
                    audio: None,
                    partial: None,
                    seq: None,
                    stream: None,
                    contact: None,
                    content_type: Some("text/plain; charset=utf-8".into()),
                    relay_of: None,
                    addressee: None,
                })
                .await
                .map_err(worker_error)?,
        )?,
        ChannelAction::Poll => serde_json::to_value(
            worker
                .poll(&ChannelPollBody {
                    cap,
                    after: options.after.clone(),
                    wait_seconds: options.wait_seconds,
                    tail: None,
                })
                .await
                .map_err(worker_error)?,
        )?,
    };
    ensure!(
        response["ok"] == true,
        "local channel operation did not succeed"
    );
    Ok(json!({"development_only":true, "channel":options.channel, "response":response}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_errors_expose_status_without_payload_or_endpoint() {
        for error in [
            BrokerError::Rejected {
                endpoint: "synthetic-private".into(),
                status: 403,
                body: "synthetic-private".into(),
            },
            BrokerError::Transport("synthetic-private".into()),
            BrokerError::Decode("synthetic-private".into()),
        ] {
            assert!(!worker_error(error)
                .to_string()
                .contains("synthetic-private"));
        }
    }
}
