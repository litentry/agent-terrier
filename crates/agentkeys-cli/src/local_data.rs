use std::io::Read;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentkeys_backend_client::{BackendClient, BackendError, CapMintRequest};
use agentkeys_core::{device_crypto::DeviceKey, protected_file};
use anyhow::{anyhow, ensure, Context, Result};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{cred_admin, local_owner::LocalOwnerSession, CommandContext};

const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;
const CAPABILITY_TTL_SECONDS: u64 = 300;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum CredentialAction {
    Store,
    Fetch,
}

#[derive(clap::Args)]
pub struct CredentialOptions {
    pub action: CredentialAction,
    pub service: String,
    #[arg(long)]
    pub operator_omni: String,
    #[arg(long)]
    pub device_key_file: String,
    #[arg(long)]
    pub session_file: String,
    #[arg(long)]
    pub broker_url: String,
    #[arg(long)]
    pub cred_url: String,
    #[arg(
        long,
        help = "Read the exact UTF-8 credential from stdin; required for store"
    )]
    pub secret_stdin: bool,
}

fn identity(value: &str) -> Result<[u8; 32]> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))?
        .try_into()
        .map_err(|_| anyhow!("invalid local owner identity"))
}

pub(crate) fn load_session(
    options: &CredentialOptions,
    key: &DeviceKey,
    now: u64,
) -> Result<LocalOwnerSession> {
    let encoded =
        protected_file::read_text(&options.session_file).context("read protected local session")?;
    let session: LocalOwnerSession =
        serde_json::from_str(&encoded).map_err(|_| anyhow!("invalid local session"))?;
    ensure!(
        session.development_only,
        "session is not explicitly development-only"
    );
    ensure!(
        session.broker_url == options.broker_url,
        "session belongs to another broker; log in again"
    );
    ensure!(
        identity(&session.session.omni_account)? == identity(&options.operator_omni)?,
        "session belongs to another owner"
    );
    ensure!(
        identity(&session.device_key_hash)? == identity(&key.device_key_hash()?)?,
        "session belongs to another request key"
    );
    ensure!(
        session.session.expires_at > now && !session.session.session_jwt.is_empty(),
        "local session expired; log in again"
    );
    Ok(session)
}

fn request_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast_ref::<BackendError>() {
        Some(BackendError::Http { status, .. }) => {
            anyhow!("local credential request failed (HTTP {status})")
        }
        Some(BackendError::Transport(_)) => anyhow!("local credential service is unreachable"),
        _ => anyhow!("local credential response is invalid or unsupported"),
    }
}

pub async fn credential(context: &CommandContext, options: &CredentialOptions) -> Result<Value> {
    let development = context.development_signing()?;
    development.require_local_service(&options.broker_url)?;
    development.require_local_service(&options.cred_url)?;
    ensure!(
        matches!(options.action, CredentialAction::Store) == options.secret_stdin,
        "only credential store requires --secret-stdin"
    );
    let key = Arc::new(
        DeviceKey::load(&options.device_key_file).context("load existing owner request key")?,
    );
    let session = load_session(
        options,
        &key,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    let client = BackendClient::with_client(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15))
            .build()?,
        Some(options.broker_url.clone()),
        None,
        None,
        Some(options.cred_url.clone()),
    )
    .with_device_key(key.clone());
    let request = CapMintRequest {
        operator_omni: options.operator_omni.clone(),
        actor_omni: options.operator_omni.clone(),
        device_key_hash: key.device_key_hash()?,
        service: options.service.clone(),
        ttl_seconds: CAPABILITY_TTL_SECONDS,
    };
    match options.action {
        CredentialAction::Store => {
            let mut secret = Zeroizing::new(String::new());
            std::io::stdin()
                .take(MAX_CREDENTIAL_BYTES + 1)
                .read_to_string(&mut secret)?;
            ensure!(
                !secret.is_empty() && secret.len() as u64 <= MAX_CREDENTIAL_BYTES,
                "credential must contain 1 to {MAX_CREDENTIAL_BYTES} UTF-8 bytes"
            );
            let object_key = cred_admin::cred_store_with(
                &client,
                request,
                &session.session.session_jwt,
                &secret,
            )
            .await
            .map_err(request_error)?;
            Ok(
                json!({"development_only":true, "stored":true, "service":options.service, "object_key":object_key}),
            )
        }
        CredentialAction::Fetch => {
            let secret =
                cred_admin::cred_fetch_with(&client, request, &session.session.session_jwt)
                    .await
                    .map_err(request_error)?;
            Ok(json!({"development_only":true, "service":options.service, "secret":secret}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentkeys_backend_client::protocol::auth::MasterSession;

    #[test]
    fn saved_session_is_bound_to_owner_key_broker_and_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("device.key");
        let key = DeviceKey::load_or_generate(key_path.to_str().unwrap(), false).unwrap();
        let options = CredentialOptions {
            action: CredentialAction::Fetch,
            service: "example".into(),
            operator_omni: format!("0x{}", "11".repeat(32)),
            device_key_file: key_path.to_str().unwrap().into(),
            session_file: directory
                .path()
                .join("session.json")
                .to_str()
                .unwrap()
                .into(),
            broker_url: "http://127.0.0.1:12345".into(),
            cred_url: "http://127.0.0.1:12346".into(),
            secret_stdin: false,
        };
        let record = LocalOwnerSession {
            development_only: true,
            broker_url: options.broker_url.clone(),
            account: format!("0x{}", "22".repeat(20)),
            device_key_hash: key.device_key_hash().unwrap(),
            session: MasterSession {
                session_jwt: "synthetic-session".into(),
                omni_account: options.operator_omni.clone(),
                wallet_address: format!("0x{}", "22".repeat(20)),
                expires_at: 100,
            },
        };
        let original = serde_json::to_value(record).unwrap();
        let save = |record: &Value| {
            protected_file::replace_atomic(
                std::path::Path::new(&options.session_file),
                &serde_json::to_vec(record).unwrap(),
            )
            .unwrap();
        };
        save(&original);
        assert!(load_session(&options, &key, 99).is_ok());
        assert!(load_session(&options, &key, 100).is_err());
        for (pointer, replacement) in [
            ("/development_only", json!(false)),
            ("/broker_url", json!("http://127.0.0.1:1")),
            ("/device_key_hash", json!(format!("0x{}", "33".repeat(32)))),
            (
                "/session/omni_account",
                json!(format!("0x{}", "44".repeat(32))),
            ),
            ("/session/session_jwt", json!("")),
            ("/session/expires_at", json!("synthetic-session")),
        ] {
            let mut changed = original.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            save(&changed);
            let error = load_session(&options, &key, 99).err().unwrap();
            assert!(!format!("{error:#}").contains("synthetic-session"));
        }
        save(&original);
        assert!(load_session(&options, &key, 99).is_ok());
    }

    #[test]
    fn service_error_reports_status_without_response_or_transport_secrets() {
        let failures = [
            BackendError::Http {
                status: 403,
                body: "synthetic-private-value".into(),
            },
            BackendError::Transport("synthetic-private-value".into()),
            BackendError::Parse("synthetic-private-value".into()),
        ];
        for failure in failures {
            let http = matches!(&failure, BackendError::Http { .. });
            let error = request_error(anyhow::Error::new(failure).context("operation failed"));
            assert!(!format!("{error:#}").contains("synthetic-private-value"));
            if http {
                assert!(error.to_string().contains("403"));
            }
        }
    }
}
