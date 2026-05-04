use std::sync::Arc;

use agentkeys_core::backend::CredentialBackend;
use agentkeys_types::{Session, WalletAddress};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{JsonRpcRequest, McpHandler};

pub async fn run_stdio(
    backend: Arc<dyn CredentialBackend>,
    session: Session,
    agent_id: WalletAddress,
) -> anyhow::Result<()> {
    let broker_url = std::env::var("AGENTKEYS_BROKER_URL").ok();
    run_stdio_with_broker(backend, session, agent_id, broker_url).await
}

pub async fn run_stdio_with_broker(
    backend: Arc<dyn CredentialBackend>,
    session: Session,
    agent_id: WalletAddress,
    broker_url: Option<String>,
) -> anyhow::Result<()> {
    let handler =
        McpHandler::new(backend, session, agent_id).with_broker_url(broker_url);
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = stdout;
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            break; // EOF
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let error_response = crate::JsonRpcResponse::error(
                    None,
                    -32700,
                    format!("parse error: {e}"),
                );
                let mut out = serde_json::to_string(&error_response)?;
                out.push('\n');
                writer.write_all(out.as_bytes()).await?;
                writer.flush().await?;
                continue;
            }
        };

        // Notifications get no response
        if request.method.starts_with("notifications/") {
            handler.handle(request).await;
            continue;
        }

        let response = handler.handle(request).await;
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}
