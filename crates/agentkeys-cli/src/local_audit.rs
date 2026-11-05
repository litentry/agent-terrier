use crate::{local_data, CommandContext};
use agentkeys_backend_client::protocol::console_chain::ConsoleConfig;
use agentkeys_core::{
    audit::{envelope_for, AuditEnvelope, AuditOpKind, AuditResult},
    device_crypto::DeviceKey,
};
use agentkeys_web_core::{
    broker::BrokerClient,
    console_audit::ConsoleAudit,
    data::{DataClient, DataEndpoints, DataSession},
};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    io::Read,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum AuditAction {
    Append,
    Fetch,
    List,
    Recent,
    Decode,
}
#[derive(clap::Args)]
pub struct AuditOptions {
    pub action: AuditAction,
    #[arg(long)]
    pub hash: Option<String>,
    #[arg(long)]
    pub id: Option<String>,
    #[arg(long)]
    pub cursor: Option<String>,
    #[arg(long)]
    pub op_kind: Option<u8>,
    #[arg(long)]
    pub body_stdin: bool,
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
}

pub async fn execute(context: &CommandContext, options: &AuditOptions) -> Result<Value> {
    context
        .development_signing()?
        .require_local_service(&options.broker_url)?;
    ensure!(
        matches!(options.action, AuditAction::Append) == options.body_stdin
            && options.body_stdin == options.op_kind.is_some(),
        "only audit append requires --op-kind and --body-stdin"
    );
    ensure!(
        matches!(options.action, AuditAction::Fetch) == options.hash.is_some(),
        "only audit fetch requires --hash"
    );
    ensure!(
        matches!(options.action, AuditAction::Decode) == options.id.is_some(),
        "only audit decode requires --id"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let key = DeviceKey::load(&options.device_key_file)?;
    let session = local_data::load_session(
        &options.session_file,
        &options.broker_url,
        &options.operator_omni,
        &key,
        now,
    )?;
    let device = local_data::browser_device(&options.device_key_file, &key)?;
    let authority = DataSession {
        bearer: &session.session.session_jwt,
        operator_omni: &options.operator_omni,
        actor_omni: &options.operator_omni,
        device: &device,
        now_unix_seconds: now,
    };
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let broker = BrokerClient::with_client(http.clone(), &options.broker_url);
    let configuration: ConsoleConfig = broker
        .console_config()
        .await
        .map_err(|_| anyhow::anyhow!("local audit configuration unavailable"))?;
    let data = DataClient::with_client(
        http,
        DataEndpoints {
            broker_url: options.broker_url.clone(),
            signer_url: configuration.signer_url.clone(),
            credential_url: configuration.credential_url.clone(),
            memory_url: configuration.memory_url.clone(),
            config_url: configuration.config_url.clone(),
            audit_url: configuration.audit_url.clone(),
            classify_url: Some(configuration.classify_url.clone()),
        },
    );
    let error = |error| local_data::data_error(error, "audit");
    match options.action {
        AuditAction::Append => {
            let mut body = Vec::new();
            std::io::stdin()
                .take(32 * 1024 + 1)
                .read_to_end(&mut body)?;
            ensure!(
                !body.is_empty() && body.len() <= 32 * 1024,
                "audit body exceeds size limit or is empty"
            );
            let body: Value = serde_json::from_slice(&body).context("invalid audit body JSON")?;
            let owner = crate::local_owner::fixed::<32>(&options.operator_omni)?;
            let kind = AuditOpKind::from_u8(options.op_kind.context("missing audit kind")?)
                .context("unknown audit operation kind")?;
            let mut envelope =
                envelope_for(owner, owner, kind, body, AuditResult::Success, None, None)?;
            envelope.ts_unix = now;
            ensure!(
                envelope.typed_body().is_some(),
                "audit body does not match operation kind"
            );
            let request = serde_json::from_value(
                agentkeys_web_core::audit::client::envelope_to_json(&envelope)?,
            )?;
            let receipt = data
                .audit_append(&authority, &request)
                .await
                .map_err(error)?;
            let expected = format!("0x{}", hex::encode(envelope.envelope_hash()?));
            ensure!(
                receipt.ok && receipt.envelope_hash == expected,
                "archive returned a different commitment"
            );
            Ok(json!({"stored":true,"anchored":false,"envelope_hash":receipt.envelope_hash}))
        }
        AuditAction::Fetch => {
            let hash = options.hash.as_deref().context("missing hash")?;
            let bytes = data.audit_fetch(&authority, hash).await.map_err(error)?;
            let envelope = AuditEnvelope::from_canonical_cbor(&bytes)?;
            ensure!(
                format!("0x{}", hex::encode(envelope.envelope_hash()?)).eq_ignore_ascii_case(hash),
                "audit envelope hash mismatch"
            );
            ensure!(
                envelope.operator_omni == crate::local_owner::fixed::<32>(&options.operator_omni)?,
                "audit envelope belongs to another owner"
            );
            Ok(json!({"envelope_hash":hash,"envelope":envelope.to_json()}))
        }
        AuditAction::List => Ok(serde_json::to_value(
            agentkeys_core::audit::AuditClient::with_bearer(
                &options.broker_url,
                authority.bearer.to_owned(),
            )
            .list_envelopes(None, options.cursor.as_deref(), options.limit)
            .await
            .context("audit index request failed")?,
        )?),
        AuditAction::Recent => {
            let mut query = format!("?limit={}", options.limit);
            if let Some(cursor) = &options.cursor {
                agentkeys_web_core::console_audit::audit_cursor(cursor)
                    .map_err(anyhow::Error::msg)?;
                query.push_str(&format!("&cursor={cursor}"));
            }
            Ok(serde_json::to_value(
                ConsoleAudit::new(broker, data, configuration)
                    .page(&authority, &query)
                    .await
                    .map_err(error)?,
            )?)
        }
        AuditAction::Decode => Ok(ConsoleAudit::new(broker, data, configuration)
            .decode(&authority, options.id.as_deref().context("missing id")?)
            .await
            .map_err(error)?),
    }
}
